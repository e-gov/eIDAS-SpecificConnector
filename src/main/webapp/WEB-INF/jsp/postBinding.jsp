<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<body>
<noscript>
    <p>
        <strong>Note:</strong> Since your browser does not support JavaScript,
        you must press the Continue button once to proceed.
    </p>
</noscript>

<form action="${action}" method="post">
    <div>
        <c:if test="${not empty token}">
            <input type="hidden" name="token" value="${token}"/>
        </c:if>
        <c:if test="${not empty SAMLResponse}">
            <input type="hidden" name="SAMLResponse" value="${SAMLResponse}"/>
        </c:if>
        <c:if test="${not empty RelayState}">
            <input type="hidden" name="RelayState" value="${RelayState}"/>
        </c:if>
    </div>
    <noscript>
        <div>
            <input type="submit" value="Continue"/>
        </div>
    </noscript>
</form>

<script type="text/javascript">document.forms[0].submit();</script>
</body>
</html>