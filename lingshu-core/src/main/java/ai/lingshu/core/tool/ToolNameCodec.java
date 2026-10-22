/*
 * Copyright 2026 The LingShu Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.lingshu.core.tool;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

/**
 * Single source of truth for translating LingShu tool names into the name
 * format required by LLM function-calling APIs.
 *
 * <p>LingShu deliberately keeps internal names unconstrained, because tool
 * names come from heterogeneous sources:
 * <ul>
 *   <li>MCP — {@code server:tool} (contains {@code ':'}, and servers may expose
 *       dots, spaces or CJK characters)</li>
 *   <li>Skills — the {@code SKILL.md} parent directory name, which may contain
 *       any character the filesystem allows</li>
 *   <li>A2A / delegate / local tools — plugin-provided strings</li>
 * </ul>
 *
 * <p>Anthropic (and OpenAI-compatible) APIs only accept
 * {@code ^[a-zA-Z0-9_-]{1,64}$}. Instead of imposing that restriction on every
 * tool source (which would break CLI {@code /skill-name} commands and existing
 * permission allow-lists), the restriction is applied once at the LLM wire
 * boundary by this codec:
 * <ul>
 *   <li>names already matching the pattern are returned unchanged;</li>
 *   <li>everything else becomes {@code <readable-prefix>_<12-hex-hash>}, where
 *       the hash is derived only from the original name — stable across
 *       requests, turns and dynamic tool-registry changes, and collision-safe
 *       even when two names sanitize to the same prefix.</li>
 * </ul>
 *
 * <p>Callers must keep a per-request {@code wireName → internalName} alias map
 * so tool calls emitted by the model can be resolved back to the registered
 * tool name.
 *
 * @since 0.1.0
 */
public final class ToolNameCodec {

    /** Maximum tool-name length accepted by Anthropic / OpenAI function calling. */
    public static final int MAX_WIRE_NAME_LENGTH = 64;

    /** Exact name format accepted by the wire protocols. */
    public static final Pattern VALID_WIRE_NAME =
        Pattern.compile("^[a-zA-Z0-9_-]{1," + MAX_WIRE_NAME_LENGTH + "}$");

    private static final int NAME_HASH_HEX_LENGTH = 12;

    private ToolNameCodec() {
        throw new AssertionError("ToolNameCodec must not be instantiated");
    }

    /**
     * Whether {@code name} can be sent to the LLM without translation.
     */
    public static boolean isWireSafe(String name) {
        return name != null && VALID_WIRE_NAME.matcher(name).matches();
    }

    /**
     * Translate an internal tool name into a legal LLM wire name.
     *
     * <p>Returns {@code null} for {@code null} so callers keep their existing
     * missing-name validation semantics.
     */
    public static String toWireName(String name) {
        if (name == null || isWireSafe(name)) {
            return name;
        }
        String hash = shortNameHash(name);
        String prefix = sanitize(name);
        int maxPrefixLength = MAX_WIRE_NAME_LENGTH - 1 - hash.length();
        if (prefix.length() > maxPrefixLength) {
            prefix = prefix.substring(0, maxPrefixLength);
        }
        int end = prefix.length();
        while (end > 0 && prefix.charAt(end - 1) == '_') {
            end--;
        }
        prefix = prefix.substring(0, end);
        if (prefix.isEmpty()) {
            prefix = "tool";
        }
        return prefix + "_" + hash;
    }

    /**
     * Replace characters outside {@code [a-zA-Z0-9_-]} with {@code '_'}.
     * Cosmetic only — uniqueness always comes from the hash suffix.
     */
    private static String sanitize(String name) {
        StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '_' || c == '-';
            sb.append(valid ? c : '_');
        }
        return sb.toString();
    }

    /**
     * Deterministic 12-hex fingerprint of the original name.
     */
    private static String shortNameHash(String name) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(name.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(NAME_HASH_HEX_LENGTH);
            for (int i = 0; i < NAME_HASH_HEX_LENGTH / 2 && i < digest.length; i++) {
                int b = digest[i] & 0xFF;
                sb.append(Character.forDigit(b >>> 4, 16));
                sb.append(Character.forDigit(b & 0x0F, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory on every Java platform; keep a stable fallback anyway.
            return Integer.toHexString(name.hashCode());
        }
    }
}
