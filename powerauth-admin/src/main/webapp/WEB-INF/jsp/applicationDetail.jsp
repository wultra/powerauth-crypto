<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>

<jsp:include page="header.jsp">
	<jsp:param name="pageTitle" value="PowerAuth 2.0 - Application Details"/>
</jsp:include>

	<ol class="breadcrumb">
		<li><a class="black" href="${pageContext.request.contextPath}/application/list">Applications</a></li>
		<li class="active">Application Detail</li>
	</ol>
	
	<div class="row">
	
		<div class="col-md-4">
			<div class="panel panel-default">
		
				<div class="panel-heading">
					<h3 class="panel-title">Application #<c:out value="${id}"/>: <c:out value="${name}"/></h3>
				</div>
				
				<div class="panel-body">
					<p>Master Public Key</p>
					<div class="well code wrap"><c:out value="${masterPublicKey}"/></div>
				</div>
				
				<div class="panel-footer">
					<a href="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/version/create" class="btn btn-success pull-right">New Version</a>
					<div class="clearfix"></div>
				</div>
			</div>
		</div>
	
		<div class="col-md-8">
			<div class="panel panel-default">
				
					<table class="table">
						<thead>
							<tr>
								<th>Version</th>
								<th>Application Key</th>
								<th>Application Secret</th>
								<th colspan="2">Supported</th>
							</tr>
						</thead>
						<tbody>
							<c:forEach items="${versions}" var="item">
								<tr class="code">
									<td><c:out value="${item.applicationVersionName}"/></td>
									<td><c:out value="${item.applicationKey}"/></td>
									<td><c:out value="${item.applicationSecret}"/></td>
									<td>
										<c:choose>
											<c:when test="${item.supported}">
												<span class="green">Yes</span>
											</c:when>
											<c:otherwise>
												<span class="red">No</span>
											</c:otherwise>
										</c:choose>
									</td>
									<td>
										<c:choose>
											<c:when test="${item.supported}">
												<form action="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/version/update/do.submit" method="POST">
													<input type="hidden" name="enabled" value="false" />
													<input type="hidden" name="version" value="<c:out value="${item.applicationVersionId}"/>" />
													<input type="submit" value="Disable" class="btn btn-sm btn-default w100"/>
												</form>
											</c:when>
											<c:otherwise>
												<form action="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/version/update/do.submit" method="POST">
													<input type="hidden" name="enabled" value="true" />
													<input type="hidden" name="version" value="<c:out value="${item.applicationVersionId}"/>" />
													<input type="submit" value="Enable" class="btn btn-sm btn-default w100"/>
												</form>
											</c:otherwise>
										</c:choose>
									</td>
								</tr>
							</c:forEach>
						</tbody>
					</table>
			</div>
		</div>
	
	</div>
	
<jsp:include page="footer.jsp"/>