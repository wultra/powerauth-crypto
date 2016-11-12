<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<c:choose>
    <c:when test="${fn:length(integrations) == 0}">
        <jsp:include page="header.jsp">
            <jsp:param name="pageTitle" value="PowerAuth 2.0 - Integrations"/>
        </jsp:include>
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">New Integration</h3>
            </div>
            <div class="panel-body">
                <form class="form-inline" action="${pageContext.request.contextPath}/integration/create/do.submit" method="POST">
                    Integration name <input type="text" name="name" class="form-control">
                    <input type="submit" value="Submit" class="btn btn-success" />
                </form>
            </div>
        </div>
    </c:when>
    <c:otherwise>
        <jsp:include page="header.jsp">
            <jsp:param name="pageTitle" value="PowerAuth 2.0 - Integrations"/>
        </jsp:include>

        <c:if test="${not restrictedAccess}">
            <div class="panel panel-danger">
                <div class="panel-heading">
                    <h3 class="panel-title">Application Security is not Enabled</h3>
                </div>
                <div class="panel-body">
                    At this moment, any application is able to call this instance of the PowerAuth 2.0 Server with
                    no restrictions as long as it can see the service. You can change this behavior and set up access
                    restriction by adding one or more "integrations". Each "integration" represents an application that
                    accesses PowerAuth 2.0 Server instance and provides access credentials (HTTP Basic in case of
                    RESTful interface, WS-Security with "username-token" security in case of SOAP interface).
                </div>
                <div class="panel-body">
                    To enable access restriction on PowerAuth 2.0 Server, set the following property for the
                    <strong>PowerAuth 2.0 Server</strong> application:
                    <div class="code">
                        powerauth.service.restrictAccess=true
                    </div>
                </div>
                <div class="panel-body">
                    Also, make sure to create at least one "integration" first and use the credentials for this instance
                    of <strong>PowerAuth 2.0 Admin</strong> application (so that it can access the service), by setting
                    following two properties:
                    <div class="code">
                        powerauth.service.security.clientToken=YOUR_CLIENT_TOKEN<br/>
                        powerauth.service.security.clientSecret=YOUR_CLIENT_SECRET
                    </div>
                </div>
            </div>
        </c:if>
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title button pull-left">Integrations</h3>
                <a href="${pageContext.request.contextPath}/integration/create" class="pull-right btn btn-success">New Integration</a>
                <div class="clearfix"></div>
            </div>
            <table class="table">
                <thead>
                <tr>
                    <th>Name</th>
                    <th>Client Token</th>
                    <th>Client Secret</th>
                </tr>
                </thead>
                <tbody>
                <c:forEach items="${integrations}" var="item">
                    <tr class="code">
                        <td><c:out value="${item.name}"/></td>
                        <td><c:out value="${item.clientToken}"/></td>
                        <td><c:out value="${item.clientSecret}"/></td>
                        <td>
                            <form action="${pageContext.request.contextPath}/integration/remove/do.submit" method="POST" class="pull-right action-remove">
                                <input type="hidden" name="integrationId" value="<c:out value="${item.id}"/>"/>
                                <input class="btn btn-danger" type="submit" value="Remove">
                            </form>
                        </td>
                    </tr>
                </c:forEach>
                </tbody>
            </table>
        </div>
    </c:otherwise>
</c:choose>

<jsp:include page="footer.jsp"/>