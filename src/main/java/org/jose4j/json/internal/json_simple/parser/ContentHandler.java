package org.jose4j.json.internal.json_simple.parser;

import java.io.IOException;

/**
 * A simplified and stoppable SAX-like content handler for stream processing of JSON text. 
 * 
 * @see org.xml.sax.ContentHandler
 * @see org.jose4j.json.internal.json_simple.parser.JSONParser#parse(java.io.Reader, ContentHandler, boolean)
 * 
 * @author (originally) FangYidong fangyidong@yahoo.com.cn
 */
public interface ContentHandler {
	/**
	 * Receive notification of the beginning of JSON processing.
	 * The parser will invoke this method only once.
     * 
	 * @throws ParseException 
	 * 			- JSONParser will stop and throw the same exception to the caller when receiving this exception.
	 * @throws IOException IOException
	 */
	void startJSON() throws ParseException, IOException;
	
	/**
	 * Receive notification of the end of JSON processing.
	 * 
	 * @throws ParseException ParseException
	 * @throws IOException IOException
	 */
	void endJSON() throws ParseException, IOException;
	
	/**
	 * Receive notification of the beginning of a JSON object.
	 * 
	 * @return false if the handler wants to stop parsing after return.
	 * @throws ParseException
     *          - JSONParser will stop and throw the same exception to the caller when receiving this exception.
	 * @throws IOException IOException
     * @see #endJSON
	 */
	boolean startObject() throws ParseException, IOException;
	
	/**
	 * Receive notification of the end of a JSON object.
	 * 
	 * @return false if the handler wants to stop parsing after return.
	 * @throws ParseException ParseException
	 * @throws IOException IOException
     * 
     * @see #startObject
	 */
	boolean endObject() throws ParseException, IOException;
	
	/**
	 * Receive notification of the beginning of a JSON object entry.
	 * 
	 * @param key - Key of a JSON object entry. 
	 * 
	 * @return false if the handler wants to stop parsing after return.
	 * @throws ParseException ParseException
	 * @throws IOException IOException
     * 
     * @see #endObjectEntry
	 */
	boolean startObjectEntry(String key) throws ParseException, IOException;
	
	/**
	 * Receive notification of the end of the value of previous object entry.
	 * 
	 * @return false if the handler wants to stop parsing after return.
	 * @throws ParseException ParseException
	 * @throws IOException IOException
     * 
     * @see #startObjectEntry
	 */
	boolean endObjectEntry() throws ParseException, IOException;
	
	/**
	 * Receive notification of the beginning of a JSON array.
	 * 
	 * @return false if the handler wants to stop parsing after return.
	 * @throws ParseException ParseException
	 * @throws IOException IOException
     * @see #endArray
	 */
	boolean startArray() throws ParseException, IOException;
	
	/**
	 * Receive notification of the end of a JSON array.
	 * 
	 * @return false if the handler wants to stop parsing after return.
	 * @throws ParseException ParseException
	 * @throws IOException IOException
     * 
     * @see #startArray
	 */
	boolean endArray() throws ParseException, IOException;
	
	/**
	 * Receive notification of the JSON primitive values:
	 * 	java.lang.String,
	 * 	java.lang.Number,
	 * 	java.lang.Boolean
	 * 	null
	 * 
	 * @param value - Instance of the following:
	 * 			java.lang.String,
	 * 			java.lang.Number,
	 * 			java.lang.Boolean
	 * 			null
	 * 
	 * @return false if the handler wants to stop parsing after return.
	 * @throws ParseException ParseException
	 * @throws IOException IOException
	 */
	boolean primitive(Object value) throws ParseException, IOException;
		
}
