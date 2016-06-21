/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
package com.prevsec.couchburp.burp.jaxbjson;

import java.io.OutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;

public final class JsonAdapter {

	// TODO - We need to change some stuff
	public static <T> T unnmarshall(Class<T> clazz, StreamSource source) throws JAXBException {
		JAXBContext jc = JAXBContext.newInstance(clazz);
		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setProperty("eclipselink.media-type", "application/json");
		JAXBElement<T> jaxbElement = unmarshaller.unmarshal(source, clazz);
		return jaxbElement.getValue();
	}

	// TODO -This probably needs work too
	public static void mashall(Object jaxbElement, OutputStream os) throws JAXBException {
		JAXBContext jc = JAXBContext.newInstance(jaxbElement.getClass());
		Marshaller marshaller = jc.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
		marshaller.setProperty("eclipselink.media-type", "application/json");
		marshaller.marshal(jaxbElement, os);
	}

}
