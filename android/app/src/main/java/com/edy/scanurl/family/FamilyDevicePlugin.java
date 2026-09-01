package com.edy.scanurl.family;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;

@CapacitorPlugin(name = "FamilyDevice")
public class FamilyDevicePlugin extends Plugin {
    private static final String KEY_ALIAS = "edy-family-device-v1";
    private static String pendingText = "";
    private static FamilyDevicePlugin active;
    private final ExecutorService requests = new ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(8), new ThreadPoolExecutor.AbortPolicy());
    private final ScheduledExecutorService deadlines = Executors.newSingleThreadScheduledExecutor();

    @Override public void load() { active = this; }
    @Override protected void handleOnDestroy() {
        if (active == this) active = null;
        requests.shutdownNow();
        deadlines.shutdownNow();
    }
    static synchronized void acceptSharedText(String text) {
        pendingText = text;
        if (active != null) active.notifyListeners("sharedLink", new JSObject().put("text", text));
    }
    private boolean trusted(PluginCall call) {
        try {
            URI uri = URI.create(getBridge().getWebView().getUrl());
            if ("https".equals(uri.getScheme()) && "localhost".equals(uri.getHost()) && uri.getPort() == -1) return true;
        } catch (RuntimeException ignored) { }
        call.reject("APP_ORIGIN_REJECTED");
        return false;
    }
    private static synchronized KeyStore deviceKeys() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(KEY_ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).build());
            generator.generateKeyPair();
        }
        return store;
    }
    private static String deviceId(byte[] spki) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(spki)) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }
    @PluginMethod public void getIdentity(PluginCall call) {
        if (!trusted(call)) return;
        try {
            byte[] spki = deviceKeys().getCertificate(KEY_ALIAS).getPublicKey().getEncoded();
            call.resolve(new JSObject().put("publicKeySpki", Base64.encodeToString(spki, Base64.NO_WRAP))
                .put("deviceId", deviceId(spki)).put("configured", !BuildConfig.FAMILY_API_ORIGIN.isEmpty()));
        } catch (Exception ignored) { call.reject("DEVICE_KEY_UNAVAILABLE"); }
    }
    @PluginMethod public void signChallenge(PluginCall call) {
        if (!trusted(call)) return;
        try {
            String message = call.getString("message", "");
            String[] lines = message.split("\n", -1);
            KeyStore store = deviceKeys();
            String id = deviceId(store.getCertificate(KEY_ALIAS).getPublicKey().getEncoded());
            if (BuildConfig.FAMILY_API_ORIGIN.isEmpty() || message.length() > 2048 || lines.length != 8
                || !"EDY-FAMILY-V1".equals(lines[0]) || !BuildConfig.FAMILY_API_ORIGIN.equals(lines[1])
                || !id.equals(lines[2]) || !lines[3].matches("[a-zA-Z0-9_-]{16,100}")
                || !lines[4].matches("[a-zA-Z0-9_-]{32,100}")
                || !signedPath(lines[5], lines[6]) || !lines[7].matches("[a-f0-9]{64}")) {
                call.reject("CHALLENGE_REJECTED"); return;
            }
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign((PrivateKey) store.getKey(KEY_ALIAS, null));
            signer.update(message.getBytes(StandardCharsets.UTF_8));
            call.resolve(new JSObject().put("signature", Base64.encodeToString(signer.sign(), Base64.NO_WRAP)));
        } catch (Exception ignored) { call.reject("DEVICE_SIGN_FAILED"); }
    }
    private static boolean signedPath(String method, String path) {
        return ("POST".equals(method) && "/family/v1/scans".equals(path))
            || ("GET".equals(method) && path.matches("/family/v1/scans/[a-f0-9-]{36}"));
    }
    @PluginMethod public void request(PluginCall call) {
        if (!trusted(call)) return;
        String method = call.getString("method", "GET");
        String path = call.getString("path", "");
        String body = call.getString("body", "");
        boolean publicPost = "POST".equals(method) && ("/family/v1/enroll".equals(path) || "/family/v1/challenge".equals(path));
        if (BuildConfig.FAMILY_API_ORIGIN.isEmpty()) { call.reject("NOT_ACTIVATED"); return; }
        if ((!publicPost && !signedPath(method, path)) || body.getBytes(StandardCharsets.UTF_8).length > 4096
            || ("GET".equals(method) && !body.isEmpty())) { call.reject("REQUEST_REJECTED"); return; }
        JSObject headers = call.getObject("headers", new JSObject());
        long enqueuedAt = android.os.SystemClock.elapsedRealtime();
        try { requests.execute(() -> {
            HttpsURLConnection connection = null;
            AtomicReference<HttpsURLConnection> current = new AtomicReference<>();
            ScheduledFuture<?> timeout = null;
            try {
                long remaining = 20000 - (android.os.SystemClock.elapsedRealtime() - enqueuedAt);
                if (remaining <= 0) throw new IllegalArgumentException();
                connection = (HttpsURLConnection) URI.create(BuildConfig.FAMILY_API_ORIGIN + path).toURL().openConnection();
                current.set(connection);
                timeout = deadlines.schedule(() -> { HttpsURLConnection activeConnection = current.get(); if (activeConnection != null) activeConnection.disconnect(); }, remaining, TimeUnit.MILLISECONDS);
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(15000);
                connection.setReadTimeout(15000);
                connection.setRequestMethod(method);
                connection.setRequestProperty("Accept", "application/json");
                for (String name : new String[]{"X-Family-Device", "X-Family-Challenge", "X-Family-Signature"}) {
                    String value = headers.optString(name, "");
                    if (!value.isEmpty()) {
                        if (!value.matches("[a-zA-Z0-9+/=_-]{1,256}")) throw new IllegalArgumentException();
                        connection.setRequestProperty(name, value);
                    }
                }
                if ("POST".equals(method)) {
                    connection.setDoOutput(true);
                    connection.setRequestProperty("Content-Type", "application/json");
                    byte[] data = body.getBytes(StandardCharsets.UTF_8);
                    connection.setFixedLengthStreamingMode(data.length);
                    try (java.io.OutputStream output = connection.getOutputStream()) { output.write(data); }
                }
                int status = connection.getResponseCode();
                if (status >= 300 && status < 400) throw new IllegalArgumentException();
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                InputStream response = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
                if (response != null) try (InputStream input = response) {
                    byte[] buffer = new byte[8192]; int count;
                    while ((count = input.read(buffer)) != -1) {
                        if (android.os.SystemClock.elapsedRealtime() - enqueuedAt >= 20000) throw new IllegalArgumentException();
                        if (bytes.size() + count > 2 * 1024 * 1024) throw new IllegalArgumentException();
                        bytes.write(buffer, 0, count);
                    }
                }
                String text = bytes.toString("UTF-8");
                JSONObject data = text.isEmpty() ? new JSONObject() : new JSONObject(text);
                call.resolve(new JSObject().put("status", status).put("data", data));
            } catch (Exception ignored) { call.reject("SERVICE_UNAVAILABLE"); }
            finally { if (timeout != null) timeout.cancel(false); current.set(null); if (connection != null) connection.disconnect(); }
        }); } catch (RejectedExecutionException ignored) { call.reject("REQUEST_QUEUE_FULL"); }
    }
    @PluginMethod public void readClipboard(PluginCall call) {
        if (!trusted(call)) return;
        try {
            ClipboardManager manager = (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = manager.getPrimaryClip();
            CharSequence value = clip != null && clip.getItemCount() > 0 ? clip.getItemAt(0).getText() : null;
            call.resolve(new JSObject().put("text", value != null && value.length() <= 8192 ? value.toString() : ""));
        } catch (RuntimeException ignored) { call.reject("CLIPBOARD_UNAVAILABLE"); }
    }
    @PluginMethod public void takeSharedLink(PluginCall call) {
        if (!trusted(call)) return;
        synchronized (FamilyDevicePlugin.class) {
            call.resolve(new JSObject().put("text", pendingText));
            pendingText = "";
        }
    }
}
