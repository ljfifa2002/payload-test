// ObfTransform.java — standalone build-time string encoder for hooker.dex.
//
// hooker.dex is built in CI with `javac + d8` directly (NOT through Gradle/AGP),
// so the AGP instrumentation API cannot reach it. This tool runs on the javac
// output .class files, BEFORE d8: it rewrites every  Obf.s("literal")  constant
// to MARK + base64(xor(utf8)) in place, so the detection vocabulary is not
// plaintext in the shipped dex. com.pecker.payload.Obf.s reverses it at runtime.
// encode() here is the exact inverse of Obf.s (XOR self-inverse + standard Base64).
//
// Usage (CI, between javac and d8):
//   javac -cp asm.jar:asm-tree.jar -d . ObfTransform.java
//   java  -cp .:asm.jar:asm-tree.jar ObfTransform <classesDir>
//
// ClassWriter(0): we only swap one String constant for another, so stack frames
// and max stack/locals are unchanged — copy them through verbatim.
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.stream.Stream;

public class ObfTransform {

    // ⚠⚠ MUST match com.pecker.payload.Obf.KEY byte-for-byte. Rotate together.
    static final int[] KEY = {
        0xA4,0xE1,0xE1,0x8F,0xA9,0xFE,0x8A,0xB0, 0x5B,0x14,0x88,0xF7,0x19,0x13,0xD4,0x55,
        0x3D,0xCD,0x27,0x2F,0xE9,0x84,0x58,0x32, 0xFA,0x56,0xF4,0xA4,0xE2,0x31,0x4F,0x73,
    };
    static final char MARK = (char) 1; // U+0001, matches Obf.MARK

    static final String OWNER = "com/pecker/payload/Obf";
    static final String NAME  = "s";
    static final String DESC  = "(Ljava/lang/String;)Ljava/lang/String;";

    static String encode(String plain) {
        byte[] b = plain.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < b.length; i++) b[i] ^= (byte) KEY[i & 31];
        return MARK + Base64.getEncoder().encodeToString(b);
    }

    static int rewrite(MethodNode m) {
        if (m.instructions == null) return 0;
        int n = 0;
        for (AbstractInsnNode insn = m.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof LdcInsnNode)) continue;
            LdcInsnNode ldc = (LdcInsnNode) insn;
            if (!(ldc.cst instanceof String)) continue;
            AbstractInsnNode nxt = ldc.getNext();              // must be the Obf.s call
            if (nxt instanceof MethodInsnNode) {
                MethodInsnNode c = (MethodInsnNode) nxt;
                if (c.getOpcode() == Opcodes.INVOKESTATIC
                        && OWNER.equals(c.owner) && NAME.equals(c.name) && DESC.equals(c.desc)) {
                    ldc.cst = encode((String) ldc.cst);
                    n++;
                }
            }
        }
        return n;
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("usage: ObfTransform <classesDir>");
            System.exit(2);
        }
        Path root = Paths.get(args[0]);
        int[] total = {0, 0}; // {literals, classes}
        try (Stream<Path> walk = Files.walk(root)) {
            for (Path p : (Iterable<Path>) walk.filter(x -> x.toString().endsWith(".class"))::iterator) {
                ClassNode cn = new ClassNode();
                new ClassReader(Files.readAllBytes(p)).accept(cn, 0);
                int n = 0;
                for (MethodNode m : cn.methods) n += rewrite(m);
                if (n > 0) {
                    ClassWriter cw = new ClassWriter(0);
                    cn.accept(cw);
                    Files.write(p, cw.toByteArray());
                    total[0] += n;
                    total[1]++;
                    System.out.println("  " + root.relativize(p) + ": " + n + " literal(s)");
                }
            }
        }
        System.out.println("ObfTransform: encoded " + total[0] + " literal(s) across " + total[1] + " class(es)");
        if (total[0] == 0) {
            System.err.println("ObfTransform: WARNING — no Obf.s() literals found; strings NOT encoded");
        }
    }
}
