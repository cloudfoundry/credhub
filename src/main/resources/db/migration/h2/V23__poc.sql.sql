CREATE SEQUENCE parent_seqeunce START WITH 1 BELONGS_TO_TABLE;
CREATE SEQUENCE child_seqeunce START WITH 1 BELONGS_TO_TABLE;

CREATE CACHED TABLE parent(
    id BIGINT DEFAULT (NEXT VALUE FOR parent_seqeunce) NOT NULL NULL_TO_DEFAULT SEQUENCE parent_seqeunce,
    name varchar(255) not null,
);

CREATE CACHED TABLE child(
    id BIGINT DEFAULT (NEXT VALUE FOR child_seqeunce) NOT NULL NULL_TO_DEFAULT SEQUENCE child_seqeunce,
    parent_id bigint not null,
    foo varchar(255) not null,
);

alter table parent add constraint parent_pkey primary key(id);
alter table child add constraint child_pkey primary key(id);

alter table child add constraint parent_id_fkey foreign key(parent_id) references parent(id);
