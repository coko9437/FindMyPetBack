package com.busanit501.findmyfet.service.post;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

@Service
@Log4j2
public class FileUploadServiceImpl implements FileUploadService {

    // .properties에서 설정한 파일 저장 경로 주입
//    @Value("${file.upload-dir}")
//    private String uploadDir;
    @Value("${upload.dir}")
    private String uploadDir;

    @Override
    public String upload(MultipartFile multipartFile) {
        // 파일이 비어있는지 확인
        if (multipartFile.isEmpty()) {
            return null;
        }

        // 원본 파일 이름 가져오기
        String originalFilename = multipartFile.getOriginalFilename();
        log.info("Original Filename: " + originalFilename);

        // UUID를 사용하여 고유한 파일 이름 생성 (파일 이름 충돌 방지)
        String uuid = UUID.randomUUID().toString();
        String storeFilename = uuid + "_" + originalFilename;


        // 저장할 전체 경로 생성
        Path savePath = Paths.get(uploadDir + storeFilename);
        log.info("Save Path: " + savePath);

        try {
            // ✅ 폴더가 없으면 생성하는 로직 추가
            File uploadDirFile = new File(uploadDir);
            if (!uploadDirFile.exists()) {
                uploadDirFile.mkdirs();
            }
            // 지정된 경로에 파일 저장
            multipartFile.transferTo(savePath);
        } catch (IOException e) {
            log.error("File upload failed.", e);
            // 예외 처리 (예: 커스텀 예외 발생)
            throw new RuntimeException("파일 업로드에 실패했습니다.", e);
        }

        // 저장된 파일의 이름(경로로 사용될 부분)을 반환
        return storeFilename;
    } // <<<<<<<<<<<< upload 메서드가 여기서 완전히 끝납니다.

    @Override // <<<<<<<<<<<< delete 메서드는 upload 메서드 밖에서 새로 시작됩니다.
    public void delete(String filename) {
        if (filename == null || filename.isEmpty()) {
            return;
        }

        // 전체 파일 경로 생성
//        File file = new File(uploadDir + filename);
//        log.info("Deleting file: " + file.getAbsolutePath());
        File file = Paths.get(uploadDir, filename).toFile();
        log.info("Deleting file: " + file.getAbsolutePath());

        // 파일이 존재하면 삭제
        if (file.exists()) {
            if (file.delete()) {
                log.info("File deleted successfully: " + filename);
            } else {
                log.warn("Failed to delete file: " + filename);
            }
        } else {
            log.warn("File not found, cannot delete: " + filename);
        }
    }
}