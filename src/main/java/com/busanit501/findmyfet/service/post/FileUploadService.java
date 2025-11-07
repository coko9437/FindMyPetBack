package com.busanit501.findmyfet.service.post;

import org.springframework.web.multipart.MultipartFile;

// 인터페이스로 분리한 이유?
// 나중에 클라우드 스토리지를 변경하더라도 이 파일의 구현체만 변경하면됨.
public interface FileUploadService {
    /**
     * 파일을 업로드하고 저장된 파일의 URL(또는 경로)을 반환합니다.
     * @param multipartFile 업로드할 파일
     * @return 저장된 파일의 접근 URL 또는 경로
     */
    String upload(MultipartFile multipartFile);

    /**
     * 지정된 URL(또는 경로)의 파일을 삭제합니다.
     * @param fileUrl 삭제할 파일의 URL 또는 경로
     */
    void delete(String fileUrl);
}

