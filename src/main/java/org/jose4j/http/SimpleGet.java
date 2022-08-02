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
package org.jose4j.http;

import java.io.IOException;
import java.net.URL;

/**
 *  A simple HTTP GET
 */
public interface SimpleGet
{
    /**
     * Make an HTTP GET request
     * @param location the HTTP(S) URL
     * @return a SimpleResponse object representing the result of the HTTP GET request
     * @throws IOException if a problem occurs with the request 
     */
    public SimpleResponse get(String location) throws IOException;
}
