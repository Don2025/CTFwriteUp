<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<html>
<head>
    <title>Web Security -- File Upload Vulnerability</title>
</head>
<body>
    <form action="${pageContext.request.contextPath}/uploadFile" method="post" enctype="multipart/form-data">
        <label>Upload image files ("jpg", "jpeg", "png", "gif", "pdf"):</label> <input type="file" name="file"/>
        <input type="submit" value="upload"/>
    </form>
    <p>Image:</p>
    <img src="${filename }"/>
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