package com.demo.upimesh.service;

/** Permanent, non-retryable rejection of an instruction (the message is a short reason code). */
public class InvalidInstructionException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public InvalidInstructionException(String reason) {
        super(reason);
    }
}
