package com.example.imageservice.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class Image {
    private Integer id;
    private String title;
    private String url;
}
