package com.beemdevelopment.aegis.services;

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.IBinder;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import com.beemdevelopment.aegis.BuildConfig;
import com.beemdevelopment.aegis.R;
import com.beemdevelopment.aegis.receivers.VaultLockReceiver;

public class NotificationService extends Service {
    private static final int NOTIFICATION_VAULT_UNLOCKED = 1;

    private static final int NOTIFICATION_BACKUP_COMPLETE = 2;

    private static final String CHANNEL_ID = "lock_status_channel";

    @Override
    public int onStartCommand(Intent intent,int flags, int startId){
        super.onStartCommand(intent, flags, startId);
        serviceMethod();
        return Service.START_STICKY;
    }

    @SuppressLint("LaunchActivityFromNotification")
    public void serviceMethod() {
        int flags = PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE;
        Intent intent = new Intent(this, VaultLockReceiver.class);
        intent.setAction(VaultLockReceiver.ACTION_LOCK_VAULT);
        intent.setPackage(BuildConfig.APPLICATION_ID);
        PendingIntent pendingIntent = PendingIntent.getBroadcast(this, 1, intent, flags);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_aegis_notification)
                .setContentTitle(getString(R.string.app_name_full))
                .setContentText(getString(R.string.vault_unlocked_state))
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setOngoing(true)
                .setContentIntent(pendingIntent);

        // NOTE: Disabled for now. See issue: #1047
        //startForeground(NOTIFICATION_VAULT_UNLOCKED, builder.build());
    }

    /**
     * Posts a notification once a scheduled vault backup has finished writing. Tapping it
     * opens the backup location so the user can confirm the export in whichever document
     * viewer they have installed.
     *
     * @param context a context able to post on the lock-status channel
     */
    public static void notifyBackupComplete(Context context) {
        //CWE-927
        //SOURCE
        Intent reviewIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("content://" + BuildConfig.FILE_PROVIDER_AUTHORITY + "/backups"));
        reviewIntent.addCategory(Intent.CATEGORY_DEFAULT);

        int flags = PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT;
        PendingIntent reviewPendingIntent = PendingIntent.getActivity(context, 0, reviewIntent, flags);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_aegis_notification)
                .setContentTitle(context.getString(R.string.app_name_full))
                .setContentText(context.getString(R.string.backup_successful))
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true)
                .setContentIntent(reviewPendingIntent);

        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
        //CWE-927
        //SINK
        notificationManager.notify(NOTIFICATION_BACKUP_COMPLETE, builder.build());
    }

    @Override
    public void onDestroy() {
        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(this);
        notificationManager.cancel(NOTIFICATION_VAULT_UNLOCKED);
        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        super.onTaskRemoved(rootIntent);
        stopSelf();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
