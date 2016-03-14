<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>

<c:choose>
	<c:when test="${param.status == 'CREATED'}">
		<form action="" method="POST" class="pull-right">
			<input type="hidden" value="<c:out value="${param.activationId}"/>"/>
			<input class="btn btn-danger" type="submit" value="Remove">
		</form>
	</c:when>
	<c:when test="${param.status == 'OTP_USED'}">
		<form action="" method="POST" class="pull-right">
			<input type="hidden" value="<c:out value="${param.activationId}"/>"/>
			<input class="btn btn-danger" type="submit" value="Remove">
		</form>
		<form action="" method="POST" class="pull-right">
			<input type="hidden" value="<c:out value="${param.activationId}"/>"/>
			<input class="btn btn-success" type="submit" value="Commit">
		</form>
	</c:when>
	<c:when test="${param.status == 'ACTIVE'}">
		<form action="" method="POST" class="pull-right">
			<input type="hidden" value="<c:out value="${param.activationId}"/>"/>
			<input class="btn btn-danger" type="submit" value="Remove">
		</form>
		<form action="" method="POST" class="pull-right">
			<input type="hidden" value="<c:out value="${param.activationId}"/>"/>
			<input class="btn btn-warning" type="submit" value="Block">
		</form>
	</c:when>
	<c:when test="${param.status == 'BLOCKED'}">
		<form action="" method="POST" class="pull-right">
			<input type="hidden" value="<c:out value="${param.activationId}"/>"/>
			<input class="btn btn-default" type="submit" value="Remove">
		</form>
		<form action="" method="POST" class="pull-right">
			<input type="hidden" value="<c:out value="${param.activationId}"/>"/>
			<input class="btn btn-danger" type="submit" value="Unblock">
		</form>
	</c:when>
</c:choose>
<div class="clearfix"></div>