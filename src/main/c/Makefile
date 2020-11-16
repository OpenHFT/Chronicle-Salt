#!/usr/bin/make -f
#
# Makefile for C code
#

# C sources to compile

TARGET_DIR := ../../../target/classes
TARGET := $(TARGET_DIR)/libbridge.so

WORKING_DIR := $(TARGET_DIR)/../jni

JAVA_CLASSES = net.openhft.chronicle.salt.Bridge

JAVA_SRC := $(subst .,/,$(JAVA_CLASSES))
JAVA_SRC := ../../../src/main/java/$(JAVA_SRC).java

JNI_STUBS := $(subst .,_,$(JAVA_CLASSES))
JNI_HEADERS := $(patsubst %,$(WORKING_DIR)/%.h,$(JNI_STUBS))
JNI_SOURCES := $(patsubst %,%.c,$(JNI_STUBS))
JNI_JAVA_SOURCES := $(patsubst %,$(TARGET_DIR)/%.class,$(subst .,/,$(JAVA_CLASSES)))

JAVA_BUILD_DIR := $(TARGET_DIR)

JAVA_HOME ?= /usr/java/default
JAVA_LIB := $(JAVA_HOME)/jre/lib
JVM_SHARED_LIBS := -L$(JAVA_LIB)/amd64/server -L$(JAVA_LIB)/i386/server  -L$(JAVA_LIB)/amd64/jrockit/ -L$(JAVA_LIB)/i386/jrockit/

CC=gcc
INCLUDES := -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux -I $(WORKING_DIR)

# classpath for javah
ifdef CLASSPATH
JAVAH_CLASSPATH = $(JAVA_BUILD_DIR):$(CLASSPATH)
else
JAVAH_CLASSPATH = $(JAVA_BUILD_DIR)
endif

.PHONY : clean

all: $(TARGET)

$(TARGET): $(JNI_HEADERS) $(JNI_SOURCES)
	$(CC) -O3 -Wall -std=c99 -shared -fPIC $(JVM_SHARED_LIBS) -ljvm -lrt $(INCLUDES) $(JNI_SOURCES) -o $(TARGET)

JAVAH := $(shell command -v javah 2> /dev/null)

$(JNI_HEADERS): $(JNI_JAVA_SOURCES)
	@mkdir -p $(TARGET_DIR)/jni
ifdef JAVAH
	javah -force -classpath $(JAVAH_CLASSPATH) -d $(WORKING_DIR) $(JAVA_CLASSES)
else
	javac -h $(WORKING_DIR) -classpath $(JAVAH_CLASSPATH) $(JAVA_SRC)
endif

clean:
	rm $(TARGET)
