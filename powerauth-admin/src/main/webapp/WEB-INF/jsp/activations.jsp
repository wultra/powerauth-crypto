<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<jsp:include page="header.jsp">
	<jsp:param name="pageTitle" value="PowerAuth 2.0 - Activations"/>
</jsp:include>


	<c:choose>
		<c:when test="${userId == null}">
			<div class="panel panel-default">
				<div class="panel-heading">
					<h3 class="panel-title">User Selection</h3>
				</div>
				<div class="panel-body">
					<form action="${pageContext.request.contextPath}/activation/list" method="GET" class="form-inline">
						Enter a user ID <input class="form-control" type="text" name="userId" value="<c:out value="${userId}"/>" />
						<input class="form-field btn btn-success" type="submit" value="Select User" />
					</form>
				</div>
			</div>
		</c:when>
		<c:otherwise>
		
			<ol class="breadcrumb">
				<li><a class="black" href="${pageContext.request.contextPath}/activation/list">User Selection</a></li>
				<li class="active">User "<c:out value="${userId}"/>"</li>
			</ol>
			
			<div class="panel panel-default">
				<div class="panel-heading">
					<h3 class="panel-title">New Activation</h3>
				</div>
				<div class="panel-body">
					<form action="${pageContext.request.contextPath}/activation/create?userId=<c:out value="${userId}"/>" class="form-inline pull-left">
						<div class="form-group">
							<select name="applicationId" class="form-control">
								<c:forEach items="${applications}" var="item">
									<option value="<c:out value="${item.id}"/>">
										<c:out value="${item.applicationName}"/>
									</option>
								</c:forEach>
							</select>
							<input type="hidden" name="userId" value="<c:out value="${userId}"/>"/>
							<input type="submit" value="Create Activation" class="btn btn-success"/>
						</div>
					</form>
				</div>
			</div>
			
			<c:if test="${fn:length(activations) > 0}">
				<div class="panel panel-default">
					<div class="panel-heading">
						<h3 class="panel-title pull-left">Activations</h3>
						<form action="${pageContext.request.contextPath}/activation/list" method="GET" class="pull-right">
							<input type="hidden" name="userId" value="<c:out value="${userId}"/>"/>
							<label style="font-weight: normal; margin: 0;">
								<input type="checkbox" name="showAll" <c:if test='${showAll}'>checked</c:if> onchange="this.form.submit()" /> Show All
							</label>
						</form>
						<div class="clearfix"></div>
					</div>
					
					<table class="table table-hover">
						<thead>
							<tr>
								<th style="width: 310px;">Activation ID</th>
								<th>Name</th>
								<th style="width: 150px;">Application</th>
								<th style="width: 80px;">Status</th>
								<th class="text-right" style="width: 150px;">Last used</th>
								<th class="text-right" style="width: 130px;">Actions</th>
							</tr>
						</thead>
						<tbody>
							<c:forEach items="${activations}" var="item">
								<c:if test="${(showAll == true) || (item.activationStatus == 'CREATED') || (item.activationStatus == 'ACTIVE') || (item.activationStatus == 'OTP_USED') || (item.activationStatus == 'BLOCKED')}">
								<tr class="code clickable-row" data-href='${pageContext.request.contextPath}/activation/detail/<c:out value="${item.activationId}"/>'>
									<td><c:out value="${item.activationId}"/></td>
									<td><c:out value="${item.activationName}"/></td>
									<td>
										<a class="black" href='${pageContext.request.contextPath}/application/detail/<c:out value="${item.applicationId}"/>'><c:out value="${item.applicationName}"/></a>
									</td>
									<td>
										<jsp:include page="activationStatusSnippet.jsp">
											<jsp:param value="${item.activationStatus}" name="status"/>
										</jsp:include>
									</td>
									<td class="text-right"><fmt:formatDate type="both" dateStyle="short" timeStyle="short" value="${item.timestampLastUsed.toGregorianCalendar().time}" /></td>
									<td>
										<jsp:include page="activationStatusForms.jsp">
											<jsp:param value="${item.activationStatus}" name="status"/>
											<jsp:param value="${item.activationId}" name="activationId"/>
											<jsp:param value="/activation/list?userId=${userId}" name="redirect"/>
										</jsp:include>
									</td>
								</tr>
								</c:if>
							</c:forEach>
						</tbody>
					</table>
				</div>
			</c:if>
		</c:otherwise>
	</c:choose>
	

<jsp:include page="footer.jsp"/>