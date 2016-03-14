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
					<h3 class="panel-title">Select a user</h3>
				</div>
				<div class="panel-body">
					<form action="${pageContext.request.contextPath}/activation/list" method="GET" class="form-inline">
						Enter a user ID: <input class="form-control" type="text" name="userId" value="${userId}" />
						<input class="form-field btn btn-success" type="submit" value="Select user" />
					</form>
				</div>
			</div>
		</c:when>
		<c:otherwise>
		
			<ol class="breadcrumb">
				<li><a class="black" href="${pageContext.request.contextPath}/activation/list">User selection</a></li>
				<li class="active">User "${userId}"</li>
			</ol>
			
			<div class="panel panel-default">
				<div class="panel-heading">
					<h3 class="panel-title">New activation</h3>
				</div>
				<div class="panel-body">
					<form action="${pageContext.request.contextPath}/activation/create?userId=${userId}" class="form-inline pull-left">
						<div class="form-group">
							<select name="applicationId" class="form-control">
								<c:forEach items="${applications}" var="item">
									<option value="${item.id}">${item.applicationName}</option>
								</c:forEach>
							</select>
							<input type="hidden" name="userId" value="${userId}"/>
							<input type="submit" value="Create activation" class="btn btn-success"/>
						</div>
					</form>
				</div>
			</div>
			
			<c:if test="${fn:length(activations) > 0}">
				<div class="panel panel-default">
					<div class="panel-heading">
						<h3 class="panel-title pull-left">Activations</h3>
						<form action="${pageContext.request.contextPath}/activation/list" method="GET" class="pull-right">
							<input type="hidden" name="userId" value="${userId}"/>
							<label style="font-weight: normal; margin: 0;">
								<input type="checkbox" name="showAll" <c:if test='${showAll}'>checked</c:if> onchange="this.form.submit()" /> Show all
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
								<tr class="code clickable-row" data-href='${pageContext.request.contextPath}/activation/detail/${item.activationId}?userId=${userId}'>
									<td>${item.activationId}</td>
									<td>${item.activationName}</td>
									<td>
										<a class="black" href='${pageContext.request.contextPath}/application/detail/${item.applicationId}'>#${item.applicationName}</a>
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