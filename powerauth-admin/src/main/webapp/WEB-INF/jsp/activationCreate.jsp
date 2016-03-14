<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>PowerAuth 2.0 Admin - New Activation</title>
</head>
<body>
	Activation ID Short: ${activationIdShort}<br>
	Activation OTP: ${activationOTP}<br>
	Activation Signature: ${activationSignature}<br>
	Activation ID: ${activationId}<br>
	<form action="${pageContext.request.contextPath}/activation/create/do.submit" method="POST">
		<input type="hidden" name="activationId" value="${activationId}"/>
		<input type="submit" value="Commit activation"/>
	</form>
</body>
</html>