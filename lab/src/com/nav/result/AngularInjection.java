package com.nav.result;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

@WebServlet("/result/angularInjection")
public class AngularInjection extends HttpServlet {
	private static final long serialVersionUID = 1L;

	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException
	{
			String input = request.getParameter("name");
			if ("patched".equals(request.getParameter("param")))
				request.setAttribute("patched", "true");
			System.out.println(request.getParameter("param"));
			request.setAttribute("userInput", input);
			request.getRequestDispatcher("/WEB-INF/result/angularInjection.jsp").forward(request, response);
	}
}
