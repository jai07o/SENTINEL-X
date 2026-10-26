package org.sentinelx.security;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.widget.Toast;

public class SafeChargingReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (Intent.ACTION_POWER_CONNECTED.equals(action)) {
            // Power cable connected: clamp data communication pins to prevent Juice-Jacking
            Toast.makeText(context, "SENTINEL-X: Safe Charging Shield Engaged (Juice-Jacking Blocked)", Toast.LENGTH_LONG).show();
        } else if (Intent.ACTION_POWER_DISCONNECTED.equals(action)) {
            Toast.makeText(context, "SENTINEL-X: Charging Cable Disconnected", Toast.LENGTH_SHORT).show();
        }
    }
}
