package com.edy.scanurl.family;

import android.content.Intent;
import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override public void onCreate(Bundle state) {
        registerPlugin(FamilyDevicePlugin.class);
        super.onCreate(state);
        receiveSharedText(getIntent());
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        receiveSharedText(intent);
    }

    private void receiveSharedText(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction()) || !"text/plain".equals(intent.getType())) return;
        try {
            CharSequence shared = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
            if (shared != null && shared.length() <= 8192) FamilyDevicePlugin.acceptSharedText(shared.toString());
            intent.removeExtra(Intent.EXTRA_TEXT);
        } catch (RuntimeException ignored) { /* An untrusted sender cannot crash the app. */ }
    }
}
