package com.beemdevelopment.aegis.importers;

import android.content.Context;

import com.beemdevelopment.aegis.R;
import com.beemdevelopment.aegis.encoding.EncodingException;
import com.beemdevelopment.aegis.encoding.Hex;
import com.beemdevelopment.aegis.ui.dialogs.Dialogs;
import com.beemdevelopment.aegis.util.IOUtils;
import com.beemdevelopment.aegis.vault.VaultEntry;
import com.topjohnwu.superuser.io.SuFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class WinAuthImporter extends DatabaseImporter {
    private static final String ENCRYPTED_PREFIX = "winauth://encrypted/";
    private static final int ITERATIONS = 2048;
    private static final int IV_SIZE = 16;

    // WinAuth 2.x wrapped password protected exports with Triple DES, 3.x switched to AES
    private static final int VERSION_LEGACY = 1;

    public WinAuthImporter(Context context) {
        super(context);
    }

    @Override
    protected SuFile getAppPath() {
        throw new UnsupportedOperationException();
    }

    @Override
    public DatabaseImporter.State read(InputStream stream, boolean isInternal) throws DatabaseImporterException {
        byte[] data;
        try {
            data = IOUtils.readAll(stream);
        } catch (IOException e) {
            throw new DatabaseImporterException(e);
        }

        String contents = new String(data, StandardCharsets.UTF_8).trim();
        if (contents.startsWith(ENCRYPTED_PREFIX)) {
            return EncryptedState.parse(requireContext(), contents.substring(ENCRYPTED_PREFIX.length()));
        }

        GoogleAuthUriImporter importer = new GoogleAuthUriImporter(requireContext());
        DatabaseImporter.State state = importer.read(new ByteArrayInputStream(data));
        return new State(state);
    }

    public static class State extends DatabaseImporter.State {
        private DatabaseImporter.State _state;

        private State(DatabaseImporter.State state) {
            super(false);
            _state = state;
        }

        @Override
        public Result convert() throws DatabaseImporterException {
            Result result = _state.convert();

            for (VaultEntry entry : result.getEntries()) {
                entry.setIssuer(entry.getName());
                entry.setName("WinAuth");
            }

            return result;
        }
    }

    public static class EncryptedState extends DatabaseImporter.State {
        private final Context _context;
        private final int _version;
        private final byte[] _salt;
        private final byte[] _data;

        private EncryptedState(Context context, int version, byte[] salt, byte[] data) {
            super(true);
            _context = context;
            _version = version;
            _salt = salt;
            _data = data;
        }

        private static EncryptedState parse(Context context, String blob) throws DatabaseImporterException {
            String[] parts = blob.split("/");
            if (parts.length != 3) {
                throw new DatabaseImporterException("Unexpected number of fields in the WinAuth export header");
            }

            try {
                return new EncryptedState(context, Integer.parseInt(parts[0]), Hex.decode(parts[1]), Hex.decode(parts[2]));
            } catch (NumberFormatException | EncodingException e) {
                throw new DatabaseImporterException(e);
            }
        }

        protected State decrypt(char[] password) throws DatabaseImporterException {
            try {
                boolean isLegacy = _version == VERSION_LEGACY;
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(password, _salt, ITERATIONS, isLegacy ? 192 : 256);
                SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), isLegacy ? "DESede" : "AES");

                byte[] decrypted;
                if (isLegacy) {
                    //CWE-327
                    //SINK
                    Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, key);
                    decrypted = cipher.doFinal(_data);
                } else {
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(_data, 0, IV_SIZE));
                    decrypted = cipher.doFinal(_data, IV_SIZE, _data.length - IV_SIZE);
                }

                GoogleAuthUriImporter importer = new GoogleAuthUriImporter(_context);
                return new State(importer.read(new ByteArrayInputStream(decrypted)));
            } catch (NoSuchAlgorithmException
                    | NoSuchPaddingException
                    | InvalidKeySpecException
                    | InvalidKeyException
                    | InvalidAlgorithmParameterException
                    | BadPaddingException
                    | IllegalBlockSizeException e) {
                throw new DatabaseImporterException(e);
            }
        }

        @Override
        public void decrypt(Context context, DecryptListener listener) {
            Dialogs.showPasswordInputDialog(context, R.string.enter_password_aegis_title, 0, (Dialogs.TextInputListener) password -> {
                try {
                    listener.onStateDecrypted(decrypt(password));
                } catch (DatabaseImporterException e) {
                    listener.onError(e);
                }
            }, dialog -> listener.onCanceled());
        }
    }
}
