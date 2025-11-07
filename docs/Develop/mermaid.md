erDiagram
USER {
BIGINT user_id PK
VARCHAR login_id "Unique"
VARCHAR password "Encrypted"
VARCHAR name
VARCHAR phone_number
VARCHAR email "Unique"
VARCHAR address
ENUM role "USER, ADMIN"
}

    POST {
        BIGINT post_id PK
        BIGINT user_id FK
        VARCHAR title
        TEXT content
        VARCHAR animal_name
        INT animal_age
        VARCHAR animal_category "예: 개, 고양이"
        VARCHAR animal_breed "예: 말티즈, 샴"
        DATETIME lost_time
        DECIMAL latitude
        DECIMAL longitude
        ENUM post_type "MISSING, SHELTER"
        ENUM status "ACTIVE, COMPLETED"
        DATETIME created_at
    }

    COMMENT {
        BIGINT comment_id PK
        BIGINT post_id FK
        BIGINT user_id FK
        TEXT content
        DATETIME created_at
    }

    IMAGE {
        BIGINT image_id PK
        BIGINT post_id FK "Nullable"
        BIGINT comment_id FK "Nullable"
        VARCHAR image_url
    }

    %% 관계 설정
    USER ||--o{ POST : "writes"
    USER ||--o{ COMMENT : "writes"
    POST ||--o{ COMMENT : "has"
    POST ||--o{ IMAGE : "contains"
    COMMENT ||--o{ IMAGE : "contains"