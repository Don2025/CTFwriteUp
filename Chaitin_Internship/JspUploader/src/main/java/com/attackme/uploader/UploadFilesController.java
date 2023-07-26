package com.attackme.uploader;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Controller
public class UploadFilesController {
    @RequestMapping("/upload")
    public String uploadPage() {
        return "/upload";
    }

    @RequestMapping("/uploadFile")
    @ApiOperation(value = "uploadFile",httpMethod = "POST")
    public String uploadFile(@RequestParam("file") MultipartFile file, Model model, HttpServletRequest request) throws IOException {
        MultipartHttpServletRequest multipartHttpServletRequest = (MultipartHttpServletRequest) request;
        Map<String, MultipartFile> fileMap = multipartHttpServletRequest.getFileMap();
        if(file.isEmpty() || fileMap.isEmpty()){
            System.out.println("文件为空");
            return "index";
        }
        String filePath = request.getSession().getServletContext().getRealPath("/uploads/");
        File savePath = new File(filePath);
        if(!savePath.exists()){
            savePath.mkdirs();
        }
        String fileName = file.getOriginalFilename();
        String suffixName = fileName.substring(fileName.lastIndexOf(".")+1);
        MultipartFile multipartFile = file;
        InputStream fileIn = null;
        List<InputStream> list = new ArrayList<InputStream>();
        for (Map.Entry<String, MultipartFile> entity : fileMap.entrySet()) {
            multipartFile = entity.getValue();
            fileName = multipartFile.getOriginalFilename();
            suffixName = fileName.substring(fileName.lastIndexOf(".")+1);
            if(!isValidFileExtension(suffixName)) {
                return "redirect:/upload?invalidFileExtension=true";
            }
            // fileName = UUID.randomUUID() + suffixName;
            try {
                fileIn = multipartFile.getInputStream();
                list.add(multipartFile.getInputStream());
                upload(fileIn, filePath, fileName);
                model.addAttribute("filename",fileName);
                return "upload";
            } catch (IOException e) {
                throw new RuntimeException(e);
            }  finally {
                if(fileIn != null){
                    fileIn.close();
                }
            }
        }
        return "upload";
    }

    public static void upload(InputStream fileIn, String filePath, String uniqueFileName) throws IOException {
        try (OutputStream fileOut = new FileOutputStream(filePath + uniqueFileName)) {
            // Buffer to read the uploaded file in chunks
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fileIn.read(buffer)) != -1) {
                fileOut.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new IOException("Failed to upload file: " + e.getMessage());
        }
    }

    private boolean isValidFileExtension(String fileExtension) {
        List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "gif");
        String lowercaseExtension = fileExtension.toLowerCase();
        return allowedExtensions.contains(lowercaseExtension);
    }
}