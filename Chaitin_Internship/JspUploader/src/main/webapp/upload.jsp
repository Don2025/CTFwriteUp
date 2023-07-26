<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>File Upload Vulnerability</title>
</head>
<body>
<h1>Web Security -- File Upload Vulnerability</h1>
<h2>Hack me, dare you?</h2>
<form action="${pageContext.request.contextPath}/uploadFile" method="post" enctype="multipart/form-data">
    <label>Upload image files ("jpg", "jpeg", "png", "gif"):</label> <input type="file" name="file"/>
    <input type="submit" value="uploadFile"/>
</form>
<p>Image:</p>
<img src="${filename}" style="max-width: 300px; max-height: 300px;"/>
<!-- Check if the "invalidFileExtension" parameter is present in the URL and display an alert -->
<script>
    function showAlert() {
        alert("Invalid file extension! Please upload a valid file.");
    }
    var invalidFileExtensionParam = "${param.invalidFileExtension}";
    if (invalidFileExtensionParam === "true") {
        showAlert();
    }
</script>
</body>
</html>
