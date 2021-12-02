package com.olx.utils;

public enum ActiveStateEnum {
    TRUE(0),
    FALSE(1);

    public final int state;

    ActiveStateEnum(int i) {
        this.state = i;
    }
}
