#!/usr/bin/make -f
#
# Makefile for C code
#

# C sources to compile

TARGET_DIR := ../../../target/classes
TARGET := $(TARGET_DIR)/libbridge.so

WORKING_DIR := $(TARGET_DIR)/../jni

JNI_OS := win32
UNAME_S:= $(shell uname -s)
ifeq ($(UNAME_S), Linux)
    JNI_OS := linux
    LRT := -lrt
endif
ifeq ($(UNAME_S), Darwin)
    JNI_OS := darwin
endif

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
# Support both legacy JRE layout and modern JDK layout where libjvm.so
# typically resides under $(JAVA_HOME)/lib/server.
JVM_SHARED_LIBS := -L"$(JAVA_LIB)/amd64/server" -L"$(JAVA_LIB)/i386/server"  -L"$(JAVA_LIB)/amd64/jrockit" -L"$(JAVA_LIB)/i386/jrockit" -L"$(JAVA_HOME)/lib/server"

CC=gcc
CFLAGS ?= -O3 -Wall -std=c99 -fstack-protector-strong -D_FORTIFY_SOURCE=2
INCLUDES := -I"$(JAVA_HOME)/include" -I"$(JAVA_HOME)/include/$(JNI_OS)" -I"$(WORKING_DIR)"
LIBS := -ljvm $(LRT) -lsodium

# classpath for javah
ifdef CLASSPATH
JAVAH_CLASSPATH = $(JAVA_BUILD_DIR):$(CLASSPATH)
else
JAVAH_CLASSPATH = $(JAVA_BUILD_DIR)
endif

.PHONY : clean

all: $(TARGET)

$(TARGET): $(JNI_HEADERS) $(JNI_SOURCES)
	$(CC) $(CFLAGS) -shared -fPIC $(JVM_SHARED_LIBS) $(INCLUDES) $(JNI_SOURCES) $(LIBS) -o $(TARGET)

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
