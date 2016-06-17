import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Arrays;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import com.prevsec.couchburp.burp.jaxbjson.DBDescriptor;
import com.prevsec.couchburp.burp.jaxbjson.JsonAdapter;
import com.prevsec.couchburp.controller.BurpController;
import com.prevsec.couchburp.ui.BurpFrame;

public class Main {
	public static int number = 0;

	public static void main(String[] args) throws JAXBException {
		BurpFrame frame = new BurpFrame();
		BurpController controller = new BurpController(frame);
	}

}
