package com.bytenya.zcipher.compiler;

import com.bytenya.zcipher.compiler.JvmToVmTranslator.CompiledMethod;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads the inlined HydraStream class produced by ZCipherCompilerMain and
 * lowers hydraInit / hydraCrypt to ZCipher VM bytecode files. Run after
 * ZCipherCompilerMain.
 */
public final class VmCompilerMain {

    public static void main(String[] args) throws IOException {
        Path inlined = Path.of("build", "generated-classes",
                "com", "bytenya", "zcipher", "HydraStream.class");
        if (!Files.exists(inlined)) {
            throw new IOException("Inlined class missing at " + inlined.toAbsolutePath()
                    + " — run ZCipherCompilerMain first.");
        }
        byte[] bytes = Files.readAllBytes(inlined);
        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

        Path outDir = Path.of("build", "generated-vm");
        Files.createDirectories(outDir);

        for (String name : new String[] {"hydraInit", "hydraCrypt"}) {
            MethodNode m = findMethod(cn, name);
            CompiledMethod cm = new JvmToVmTranslator(cn, m).translate();
            Path outFile = outDir.resolve(name + ".vmb");
            Files.write(outFile, cm.bytecode);
            System.out.printf("%-12s %5d bytes  scratch=%5d  regs=%4d  args=%d%n",
                    name, cm.bytecode.length, cm.scratchSize, cm.regCount, cm.argRegs);
            System.out.println("           -> " + outFile.toAbsolutePath());
        }
    }

    private static MethodNode findMethod(ClassNode cn, String name) {
        for (MethodNode m : cn.methods) {
            if (m.name.equals(name)) return m;
        }
        throw new IllegalStateException("method " + name + " not found");
    }
}