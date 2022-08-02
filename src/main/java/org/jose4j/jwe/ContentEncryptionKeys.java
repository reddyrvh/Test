/*
 * Copyright 2012-2017 Brian Campbell
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

package org.jose4j.jwe;

import org.jose4j.lang.ByteUtil;

/**
*/
public class ContentEncryptionKeys
{
    private final byte[] contentEncryptionKey;
    private final byte[] encryptedKey;

    public ContentEncryptionKeys(byte[] contentEncryptionKey, byte[] encryptedKey)
    {
        this.contentEncryptionKey = contentEncryptionKey;
        this.encryptedKey = encryptedKey == null ? ByteUtil.EMPTY_BYTES : encryptedKey;
    }

    public byte[] getContentEncryptionKey()
    {
        return contentEncryptionKey;
    }

    public byte[] getEncryptedKey()
    {
        return encryptedKey;
    }
}
