package org.jose4j.json.internal.json_simple;

import java.io.IOException;
import java.io.Writer;

/**
 * Beans that support customized output of JSON text to a writer shall implement this interface.  
 * @author (originally) FangYidong fangyidong@yahoo.com.cn
 */
public interface JSONStreamAware {
	/**
	 * write JSON string to out.
	 * @param out Writer
	 * @throws IOException IOException
	 */
	void writeJSONString(Writer out) throws IOException;
}
