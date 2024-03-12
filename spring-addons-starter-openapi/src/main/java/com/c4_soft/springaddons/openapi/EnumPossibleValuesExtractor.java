package com.c4_soft.springaddons.openapi;

import java.util.Set;

public interface EnumPossibleValuesExtractor {
	Set<String> getValues(Class<Enum<?>> enumClass);
}