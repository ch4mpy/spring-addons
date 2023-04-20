package com.c4soft.springaddons.samples.bff.users.web;

import jakarta.validation.constraints.NotEmpty;

public record GreetingDto(@NotEmpty String message) {
}