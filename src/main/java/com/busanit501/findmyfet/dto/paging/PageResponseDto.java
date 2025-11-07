package com.busanit501.findmyfet.dto.paging;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.List;

@Getter
@ToString

public class PageResponseDto<E> {

    private int page;
    private int size;
    private int total;
    private int start;
    private int end;

    private boolean prev;
    private boolean next;

    private List<E> dtoList;

    // 빌더 패턴을 이용한, 생성자 구성,
    @Builder(builderMethodName = "withAll")
    public PageResponseDto(PageRequestDto pageRequestDTO, List<E> dtoList, int total) {
        this.page = pageRequestDTO.getPage();
        this.size = pageRequestDTO.getSize();

        this.total = total;
        this.dtoList = dtoList;

        // 5) 시작 페이지
        // 6) 끝 페이지
        // 7) 이전 페이지 여부
        // 8) 다음 페이지 여부
        this.end = (int) (Math.ceil(this.page / 10.0)) * 10;
        this.start = this.end - 9;
        int last = (int) (Math.ceil((total / (double) size)));
        this.end = end > last ? last : end;
        this.prev = this.start > 1;
        this.next = total > this.end * this.size;
    }
}