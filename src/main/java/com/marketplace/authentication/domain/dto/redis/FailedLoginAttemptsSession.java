package com.marketplace.authentication.domain.dto.redis;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class FailedLoginAttemptsSession {

    private byte entryAttemptsRemaining = 5;

    public void decrementEntryAttemptsRemaining() {
        this.entryAttemptsRemaining--;
    }
}
