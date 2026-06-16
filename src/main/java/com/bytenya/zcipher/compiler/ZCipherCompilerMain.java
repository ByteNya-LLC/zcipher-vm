package com.bytenya.zcipher.compiler;

import com.bytenya.zcipher.HydraStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;

public class ZCipherCompilerMain {
    static void main(String[] args) throws IOException {
        ClassNode classNode = new ClassNode();
        try (InputStream in = HydraStream.class.getResourceAsStream("HydraStream.class")) {
            if (in == null) {
                throw new IOException("HydraStream.class not found on classpath");
            }
            ClassReader reader = new ClassReader(in);
            reader.accept(classNode, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        }

        new HydraInlinePass().transform(classNode);

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
            @Override
            protected ClassLoader getClassLoader() {
                return HydraStream.class.getClassLoader();
            }
        };
        classNode.accept(writer);
        byte[] bytes = writer.toByteArray();

        CheckClassAdapter.verify(new ClassReader(bytes), false, new PrintWriter(System.err));

        Path outPath = Path.of("build", "generated-classes",
                "com", "bytenya", "zcipher", "HydraStream.class");
        Files.createDirectories(outPath.getParent());
        Files.write(outPath, bytes);

        System.out.println("Inlined HydraStream -> " + outPath.toAbsolutePath()
                + " (" + bytes.length + " bytes)");
    }
}
