package com.beemdevelopment.aegis.ui.dialogs;

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.InflateException;
import android.view.LayoutInflater;
import android.view.View;
import android.webkit.WebView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;

import com.beemdevelopment.aegis.R;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.common.io.CharStreams;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * In-app browser used to finish issuer-side enrollment. An otpauth deep link may carry a
 * "portal" link pointing at the issuer's provisioning page; that page is loaded here so the
 * user can complete setup and hand the result back to Aegis without leaving the app.
 */
public class IssuerPortalDialog extends DialogFragment {
    private static final String ARG_PORTAL_URL = "portal_url";

    public static IssuerPortalDialog newInstance(String portalUrl) {
        IssuerPortalDialog dialog = new IssuerPortalDialog();
        Bundle args = new Bundle();
        args.putString(ARG_PORTAL_URL, portalUrl);
        dialog.setArguments(args);
        return dialog;
    }

    @SuppressLint({"InflateParams", "SetJavaScriptEnabled"})
    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        final View view;
        try {
            view = LayoutInflater.from(requireContext()).inflate(R.layout.dialog_web_view, null);
        } catch (InflateException e) {
            e.printStackTrace();
            return new MaterialAlertDialogBuilder(requireContext())
                    .setTitle(android.R.string.dialog_alert_title)
                    .setMessage(getString(R.string.webview_error))
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
        }

        AlertDialog dialog = new MaterialAlertDialogBuilder(requireContext())
                .setView(view)
                .setPositiveButton(android.R.string.ok, null)
                .show();

        String portalUrl = requireArguments().getString(ARG_PORTAL_URL, "");
        final WebView webView = view.findViewById(R.id.web_view);
        // The issuer portal is an interactive enrollment page, so scripting has to be turned
        // on for its form to submit and report the provisioning result back to Aegis.
        webView.getSettings().setJavaScriptEnabled(true);
        //CWE-749
        //SINK
        webView.addJavascriptInterface(new IssuerPortalBridge(requireContext()), "AegisPortal");
        //CWE-601
        //SINK
        webView.loadUrl(portalUrl);
        // Some issuer portals still serve their provisioning assets over plain HTTP, so let the
        // HTTPS enrollment page pull them in instead of rendering a broken form to the user.
        //CWE-829
        //SINK
        webView.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        return dialog;
    }

    /**
     * Bridge backing the enrollment page, letting it read back a provisioning file that Aegis
     * wrote into its private storage during setup so the portal can confirm what was imported.
     */
    private static final class IssuerPortalBridge {
        private final Context _context;

        IssuerPortalBridge(Context context) {
            _context = context;
        }

        @android.webkit.JavascriptInterface
        public String readAppFile(String name) {
            if (name == null || name.isEmpty()) {
                return null;
            }

            File file = new File(_context.getFilesDir(), name);
            try (InputStream inStream = new FileInputStream(file);
                 InputStreamReader reader = new InputStreamReader(inStream, StandardCharsets.UTF_8)) {
                return CharStreams.toString(reader);
            } catch (IOException e) {
                return null;
            }
        }
    }
}
