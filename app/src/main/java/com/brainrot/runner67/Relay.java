package com.brainrot.runner67;

import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/** Kleiner WebSocket-Server direkt auf dem Handy: leitet jede Nachricht an alle anderen weiter. */
public class Relay extends Thread {
    private final ServerSocket ss;
    private final List<Client> clients = new CopyOnWriteArrayList<>();
    private volatile boolean running = true;

    public Relay(int port) throws IOException {
        ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(port));
        setDaemon(true);
    }

    @Override public void run() {
        while (running) {
            try {
                Socket s = ss.accept();
                s.setTcpNoDelay(true);
                new Client(s).start();
            } catch (IOException e) {
                if (!running) break;
            }
        }
    }

    public void shutdown() {
        running = false;
        try { ss.close(); } catch (IOException ignored) {}
        for (Client c : clients) c.close();
    }

    void broadcast(Client from, String msg) {
        for (Client c : clients) if (c != from) c.send(msg);
    }

    class Client extends Thread {
        final Socket s; final InputStream in; final OutputStream out;
        Client(Socket s) throws IOException {
            this.s = s; in = new BufferedInputStream(s.getInputStream()); out = s.getOutputStream(); setDaemon(true);
        }
        @Override public void run() {
            try {
                if (!handshake()) return;
                clients.add(this);
                while (true) {
                    String m = readFrame();
                    if (m == null) break;
                    if (m.length() > 0) broadcast(this, m);
                }
            } catch (Exception ignored) {
            } finally { clients.remove(this); close(); }
        }
        boolean handshake() throws Exception {
            String line, key = null;
            while ((line = readLine()) != null && line.length() > 0) {
                int i = line.indexOf(':');
                if (i > 0 && line.substring(0, i).trim().equalsIgnoreCase("Sec-WebSocket-Key")) key = line.substring(i + 1).trim();
            }
            if (key == null) return false;
            byte[] sha = MessageDigest.getInstance("SHA-1").digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes("UTF-8"));
            out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + b64(sha) + "\r\n\r\n").getBytes("UTF-8"));
            out.flush();
            return true;
        }
        String readLine() throws IOException {
            StringBuilder sb = new StringBuilder(); int c;
            while ((c = in.read()) != -1) { if (c == '\n') break; if (c != '\r') sb.append((char) c); if (sb.length() > 8192) return null; }
            if (c == -1 && sb.length() == 0) return null;
            return sb.toString();
        }
        int rd() throws IOException { int c = in.read(); if (c < 0) throw new EOFException(); return c; }
        String readFrame() throws IOException {
            ByteArrayOutputStream msg = new ByteArrayOutputStream();
            while (true) {
                int b0 = rd(), b1 = rd(), op = b0 & 0x0F; boolean fin = (b0 & 0x80) != 0;
                long len = b1 & 0x7F;
                if (len == 126) len = (rd() << 8) | rd();
                else if (len == 127) { len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | rd(); }
                if (len > 65536) return null;
                boolean masked = (b1 & 0x80) != 0; byte[] mask = new byte[4];
                if (masked) for (int i = 0; i < 4; i++) mask[i] = (byte) rd();
                byte[] p = new byte[(int) len]; int r = 0;
                while (r < len) { int n = in.read(p, r, (int) len - r); if (n < 0) throw new EOFException(); r += n; }
                if (masked) for (int i = 0; i < len; i++) p[i] ^= mask[i % 4];
                if (op == 8) return null;
                if (op == 9) { sendFrame(10, p); continue; }
                if (op == 10) continue;
                msg.write(p);
                if (fin) return new String(msg.toByteArray(), "UTF-8");
            }
        }
        synchronized void sendFrame(int op, byte[] p) {
            try {
                ByteArrayOutputStream h = new ByteArrayOutputStream();
                h.write(0x80 | op);
                if (p.length < 126) h.write(p.length);
                else if (p.length < 65536) { h.write(126); h.write(p.length >> 8); h.write(p.length & 255); }
                else { h.write(127); for (int i = 7; i >= 0; i--) h.write((int) (((long) p.length >> (8 * i)) & 255)); }
                h.write(p);
                out.write(h.toByteArray()); out.flush();
            } catch (IOException e) { close(); }
        }
        void send(String m) { try { sendFrame(1, m.getBytes("UTF-8")); } catch (UnsupportedEncodingException ignored) {} }
        void close() { try { s.close(); } catch (IOException ignored) {} }
    }

    static String b64(byte[] d) {
        String A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < d.length; i += 3) {
            int n = (d[i] & 255) << 16 | (i + 1 < d.length ? (d[i + 1] & 255) << 8 : 0) | (i + 2 < d.length ? d[i + 2] & 255 : 0);
            sb.append(A.charAt(n >> 18 & 63)).append(A.charAt(n >> 12 & 63));
            sb.append(i + 1 < d.length ? A.charAt(n >> 6 & 63) : '=').append(i + 2 < d.length ? A.charAt(n & 63) : '=');
        }
        return sb.toString();
    }

    /** IP-Adresse im WLAN bzw. Hotspot. */
    public static String localIp() {
        try {
            String best = null;
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address && a.isSiteLocalAddress()) {
                        String n = ni.getName(), ip = a.getHostAddress();
                        if (n.startsWith("wlan") || n.startsWith("ap") || n.startsWith("swlan") || n.startsWith("softap")) return ip;
                        if (best == null) best = ip;
                    }
                }
            }
            return best == null ? "" : best;
        } catch (Exception e) { return ""; }
    }

    public static void main(String[] a) throws Exception { new Relay(6767).run(); }
}
