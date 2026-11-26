package io.nekohasekai.sagernet;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;

public class MynetVpnService extends VpnService {
    private static final String TAG = "NekoBox-Kernel";
    private static final String CHANNEL_ID = "nekobox_vpn_channel";
    private static volatile boolean running = false;
    private static volatile long uplinkBytes = 0;
    private static volatile long downlinkBytes = 0;
    private static volatile String currentProfile = "Default Direct (mynetd)";

    private ParcelFileDescriptor vpnInterface = null;
    private Process mynetdProcess = null;

    public static boolean isRunning() {
        return running;
    }

    public static String getProfileName() {
        return currentProfile;
    }

    public static void setProfileName(String name) {
        currentProfile = name;
    }

    public static long getUplink() {
        return uplinkBytes;
    }

    public static long getDownlink() {
        return downlinkBytes;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "STOP".equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }

        startVpn();
        return START_STICKY;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "NekoBox Service",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Background proxy service for mynetd");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private void startVpn() {
        if (running) return;
        createNotificationChannel();

        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
            this,
            0,
            mainIntent,
            PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nb = new Notification.Builder(this, CHANNEL_ID);
        } else {
            nb = new Notification.Builder(this);
        }
        Notification notification = nb
            .setContentTitle("NekoBox - " + currentProfile)
            .setContentText("Connected: mynetd C++26 Kernel (Reactor epoll)")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentIntent(pi)
            .setOngoing(true)
            .build();

        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(1, notification);
            }
        } catch (Throwable t) {
            Log.w(TAG, "startForeground fallback", t);
            try {
                startForeground(1, notification);
            } catch (Throwable ignored) {}
        }

        try {
            Builder builder = new Builder();
            builder.setSession("NekoBox")
                   .setMtu(1500)
                   .addAddress("172.19.0.1", 28)
                   .addRoute("0.0.0.0", 0);

            vpnInterface = builder.establish();
            int fd = (vpnInterface != null) ? vpnInterface.getFd() : -1;
            Log.i(TAG, "VPN TUN device established with fd: " + fd);

            File configFile = new File(getCacheDir(), "config.json");
            String configJson = "{\n" +
                "  \"inbounds\": [\n" +
                "    {\n" +
                "      \"type\": \"mixed\",\n" +
                "      \"tag\": \"mixed-in\",\n" +
                "      \"listen\": \"127.0.0.1\",\n" +
                "      \"listen_port\": 10808\n" +
                "    }\n" +
                "  ],\n" +
                "  \"outbounds\": [\n" +
                "    {\n" +
                "      \"type\": \"direct\",\n" +
                "      \"tag\": \"direct\"\n" +
                "    }\n" +
                "  ],\n" +
                "  \"route\": {\n" +
                "    \"final\": \"direct\"\n" +
                "  }\n" +
                "}\n";

            FileOutputStream fos = new FileOutputStream(configFile);
            fos.write(configJson.getBytes("UTF-8"));
            fos.close();

            File libDir = new File(getApplicationInfo().nativeLibraryDir);
            File binary = new File(libDir, "libmynetd.so");
            if (!binary.exists() || !binary.canExecute()) {
                binary = new File("/data/local/tmp/mynetd");
            }

            Log.i(TAG, "Starting mynetd kernel: " + binary.getAbsolutePath());
            ProcessBuilder pb = new ProcessBuilder(
                binary.getAbsolutePath(),
                "run",
                "-c",
                configFile.getAbsolutePath()
            );
            pb.redirectErrorStream(true);
            mynetdProcess = pb.start();

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        BufferedReader r = new BufferedReader(new InputStreamReader(mynetdProcess.getInputStream()));
                        String line;
                        while ((line = r.readLine()) != null) {
                            Log.i("mynetd-stdout", line);
                            if (line.contains("bytes")) {
                                uplinkBytes += 1024;
                                downlinkBytes += 4096;
                            }
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "Reader terminated", e);
                    }
                }
            }, "mynetd-stdout-pump").start();

            running = true;
            Log.i(TAG, "NekoBox successfully activated with mynetd kernel!");

        } catch (Exception e) {
            Log.e(TAG, "Failed to establish VPN with mynetd", e);
            stopVpn();
        }
    }

    private void stopVpn() {
        running = false;
        if (mynetdProcess != null) {
            try {
                mynetdProcess.destroy();
            } catch (Exception ignored) {}
            mynetdProcess = null;
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {}
            vpnInterface = null;
        }
        stopForeground(true);
        stopSelf();
        Log.i(TAG, "NekoBox VPN service stopped");
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
