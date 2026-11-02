package org.example.keygen.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;

/**
 * Encapsulates client connection state in NIO Selector.
 */
public class ClientSession {

    public enum State {
        READING_NAME,
        WAITING_CRYPTO,
        WRITING_RESPONSE,
        COMPLETED,
        CLOSED
    }

    public static final int MAX_NAME_LENGTH = 256;

    private final SocketChannel channel;
    private final ByteArrayOutputStream nameBytes = new ByteArrayOutputStream();
    private volatile State state = State.READING_NAME;
    private String clientName;
    private ByteBuffer writeBuffer;
    private SelectionKey selectionKey;

    public ClientSession(SocketChannel channel) {
        this.channel = channel;
    }

    /**
     * Reads bytes from buffer until terminal null byte '\0' is found.
     *
     * @param buffer byte buffer containing newly read bytes
     * @return {@code true} if name has been read completely (found 0x00), else {@code false}
     * @throws IllegalArgumentException if name exceeds {@link #MAX_NAME_LENGTH}
     */
    public boolean readNameBytes(ByteBuffer buffer) {
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            if (b == 0) {
                this.clientName = nameBytes.toString(StandardCharsets.US_ASCII).trim();
                this.state = State.WAITING_CRYPTO;
                return true;
            }
            nameBytes.write(b);
            if (nameBytes.size() > MAX_NAME_LENGTH) {
                throw new IllegalArgumentException("Client name exceeds limit of " + MAX_NAME_LENGTH + " bytes");
            }
        }
        return false;
    }

    /**
     * Prepares outbound buffer with PEM payload.
     *
     * @param payload string data to send
     */
    public void prepareOutboundPayload(String payload) {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        this.writeBuffer = ByteBuffer.wrap(bytes);
        this.state = State.WRITING_RESPONSE;
    }

    /**
     * Flushes bytes from writeBuffer to socket channel.
     *
     * @return {@code true} if all bytes were sent, else {@code false}
     * @throws IOException on socket errors
     */
    public boolean flush() throws IOException {
        if (writeBuffer == null) {
            return true;
        }
        channel.write(writeBuffer);
        if (!writeBuffer.hasRemaining()) {
            this.state = State.COMPLETED;
            return true;
        }
        return false;
    }

    public void close() {
        this.state = State.CLOSED;
        try {
            if (channel.isOpen()) {
                channel.close();
            }
        } catch (IOException ignored) {
        }
    }

    public SocketChannel getChannel() {
        return channel;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public String getClientName() {
        return clientName;
    }

    public SelectionKey getSelectionKey() {
        return selectionKey;
    }

    public void setSelectionKey(SelectionKey selectionKey) {
        this.selectionKey = selectionKey;
    }
}
