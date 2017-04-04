#!/bin/bash

./gradlew checkstyleMain && ./gradlew checkstyleTest && ./gradlew --no-daemon clean test
