package com.bytenya.zcipher.compiler;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class HydraInlinePass {

    private static final String HYDRA_OWNER = "com/bytenya/zcipher/HydraStream";
    private static final String STATE_DESC = "Lcom/bytenya/zcipher/HydraStream$State;";
    private static final Set<String> ENTRY_POINT_NAMES = Set.of("hydraInit", "hydraCrypt");
    private static final Set<String> KEEP_NAMES = Set.of("hydraInit", "hydraCrypt", "<init>", "<clinit>");

    public void transform(ClassNode cn) {
        Map<String, MethodNode> byKey = new HashMap<>();
        for (MethodNode m : cn.methods) {
            byKey.put(m.name + m.desc, m);
        }

        List<MethodNode> targets = new ArrayList<>();
        for (MethodNode m : cn.methods) {
            if ((m.access & Opcodes.ACC_STATIC) != 0 && !"<clinit>".equals(m.name)) {
                targets.add(m);
            }
        }

        Map<MethodNode, Set<MethodNode>> calls = new IdentityHashMap<>();
        Set<MethodNode> targetSet = Collections.newSetFromMap(new IdentityHashMap<>());
        targetSet.addAll(targets);
        for (MethodNode m : targets) {
            calls.put(m, findHelperCalleesIn(m, byKey, targetSet));
        }

        List<MethodNode> sorted = topologicalSort(targets, calls);

        for (MethodNode caller : sorted) {
            if ("hydraKeystream".equals(caller.name)) {
                continue;
            }
            inlineAllCallsInto(cn, caller, byKey);
        }

        cn.methods.removeIf(m ->
                (m.access & Opcodes.ACC_STATIC) != 0
                        && !KEEP_NAMES.contains(m.name));

        for (MethodNode m : cn.methods) {
            if (!ENTRY_POINT_NAMES.contains(m.name)) continue;
            for (AbstractInsnNode insn : m.instructions.toArray()) {
                if (insn instanceof MethodInsnNode mi
                        && mi.getOpcode() == Opcodes.INVOKESTATIC
                        && HYDRA_OWNER.equals(mi.owner)) {
                    throw new IllegalStateException(
                            "Inlining missed call to " + mi.name + mi.desc + " in " + m.name);
                }
            }
        }
    }

    private Set<MethodNode> findHelperCalleesIn(MethodNode m,
                                                Map<String, MethodNode> byKey,
                                                Set<MethodNode> targetSet) {
        Set<MethodNode> result = Collections.newSetFromMap(new IdentityHashMap<>());
        for (AbstractInsnNode insn : m.instructions.toArray()) {
            if (insn instanceof MethodInsnNode mi
                    && mi.getOpcode() == Opcodes.INVOKESTATIC
                    && HYDRA_OWNER.equals(mi.owner)) {
                MethodNode callee = byKey.get(mi.name + mi.desc);
                if (callee != null && targetSet.contains(callee)) {
                    result.add(callee);
                }
            }
        }
        return result;
    }

    private List<MethodNode> topologicalSort(List<MethodNode> nodes,
                                             Map<MethodNode, Set<MethodNode>> calls) {
        List<MethodNode> result = new ArrayList<>();
        Set<MethodNode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        for (MethodNode m : nodes) {
            visit(m, calls, visited, result);
        }
        return result;
    }

    private void visit(MethodNode m,
                       Map<MethodNode, Set<MethodNode>> calls,
                       Set<MethodNode> visited,
                       List<MethodNode> result) {
        if (visited.contains(m)) return;
        visited.add(m);
        Set<MethodNode> callees = calls.get(m);
        if (callees != null) {
            for (MethodNode c : callees) {
                visit(c, calls, visited, result);
            }
        }
        result.add(m);
    }

    private void inlineAllCallsInto(ClassNode cn, MethodNode caller, Map<String, MethodNode> byKey) {
        boolean changed;
        do {
            changed = false;
            for (AbstractInsnNode insn : caller.instructions.toArray()) {
                if (insn instanceof MethodInsnNode mi
                        && mi.getOpcode() == Opcodes.INVOKESTATIC
                        && HYDRA_OWNER.equals(mi.owner)) {
                    MethodNode callee = byKey.get(mi.name + mi.desc);
                    if (callee != null
                            && !ENTRY_POINT_NAMES.contains(callee.name)
                            && callee != caller) {
                        inlineCall(cn, caller, mi, callee);
                        changed = true;
                        break;
                    }
                }
            }
        } while (changed);
    }

    private void inlineCall(ClassNode cn, MethodNode caller, MethodInsnNode invoke, MethodNode callee) {
        Type[] argTypes = Type.getArgumentTypes(invoke.desc);

        int totalArgSlots = 0;
        for (Type t : argTypes) totalArgSlots += t.getSize();

        Frame<SourceValue> frameAtInvoke = null;
        if (totalArgSlots > 0) {
            try {
                Analyzer<SourceValue> analyzer = new Analyzer<>(new SourceInterpreter());
                Frame<SourceValue>[] frames = analyzer.analyze(cn.name, caller);
                int invokeIdx = caller.instructions.indexOf(invoke);
                frameAtInvoke = frames[invokeIdx];
            } catch (AnalyzerException e) {
                frameAtInvoke = null;
            }
        }

        int slotOffset = caller.maxLocals;

        boolean stateRemapped = false;
        int sharedStateSlot = -1;
        AbstractInsnNode aloadToRemove = null;

        if (argTypes.length > 0
                && STATE_DESC.equals(argTypes[0].getDescriptor())
                && frameAtInvoke != null
                && !calleeWritesSlotZero(callee)) {
            int firstArgStackPos = frameAtInvoke.getStackSize() - totalArgSlots;
            if (firstArgStackPos >= 0) {
                SourceValue src = frameAtInvoke.getStack(firstArgStackPos);
                if (src.insns.size() == 1) {
                    AbstractInsnNode srcInsn = src.insns.iterator().next();
                    if (srcInsn instanceof VarInsnNode vi && vi.getOpcode() == Opcodes.ALOAD) {
                        stateRemapped = true;
                        sharedStateSlot = vi.var;
                        aloadToRemove = vi;
                    }
                }
            }
        }

        final boolean shareState = stateRemapped;
        final int stateSlot = sharedStateSlot;

        // Param slot positions in callee's frame
        int[] paramSlots = new int[argTypes.length];
        int slotCursor = 0;
        for (int i = 0; i < argTypes.length; i++) {
            paramSlots[i] = slotCursor;
            slotCursor += argTypes[i].getSize();
        }

        InsnList prologue = new InsnList();
        for (int i = argTypes.length - 1; i >= 0; i--) {
            if (i == 0 && shareState) continue;
            int storeOpcode = argTypes[i].getOpcode(Opcodes.ISTORE);
            int targetSlot = slotOffset + paramSlots[i];
            prologue.add(new VarInsnNode(storeOpcode, targetSlot));
        }

        Map<LabelNode, LabelNode> labelMap = new HashMap<>();
        LabelNode endLabel = new LabelNode();
        InsnList body = new InsnList();

        for (AbstractInsnNode insn = callee.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int type = insn.getType();
            if (type == AbstractInsnNode.FRAME || type == AbstractInsnNode.LINE) {
                continue;
            }

            if (insn instanceof LabelNode ln) {
                LabelNode cloned = labelMap.computeIfAbsent(ln, k -> new LabelNode());
                body.add(cloned);
                continue;
            }

            int op = insn.getOpcode();
            if (op == Opcodes.RETURN || op == Opcodes.IRETURN || op == Opcodes.LRETURN
                    || op == Opcodes.FRETURN || op == Opcodes.DRETURN || op == Opcodes.ARETURN) {
                body.add(new JumpInsnNode(Opcodes.GOTO, endLabel));
                continue;
            }

            if (insn instanceof VarInsnNode vi) {
                int newSlot = remapSlot(vi.var, slotOffset, shareState, stateSlot);
                body.add(new VarInsnNode(vi.getOpcode(), newSlot));
                continue;
            }
            if (insn instanceof IincInsnNode ii) {
                int newSlot = remapSlot(ii.var, slotOffset, shareState, stateSlot);
                body.add(new IincInsnNode(newSlot, ii.incr));
                continue;
            }

            if (insn instanceof JumpInsnNode jin) {
                LabelNode target = labelMap.computeIfAbsent(jin.label, k -> new LabelNode());
                body.add(new JumpInsnNode(jin.getOpcode(), target));
                continue;
            }
            if (insn instanceof TableSwitchInsnNode ts) {
                LabelNode dflt = labelMap.computeIfAbsent(ts.dflt, k -> new LabelNode());
                LabelNode[] labels = new LabelNode[ts.labels.size()];
                for (int i = 0; i < ts.labels.size(); i++) {
                    labels[i] = labelMap.computeIfAbsent(ts.labels.get(i), k -> new LabelNode());
                }
                body.add(new TableSwitchInsnNode(ts.min, ts.max, dflt, labels));
                continue;
            }
            if (insn instanceof LookupSwitchInsnNode ls) {
                LabelNode dflt = labelMap.computeIfAbsent(ls.dflt, k -> new LabelNode());
                LabelNode[] labels = new LabelNode[ls.labels.size()];
                for (int i = 0; i < ls.labels.size(); i++) {
                    labels[i] = labelMap.computeIfAbsent(ls.labels.get(i), k -> new LabelNode());
                }
                int[] keys = new int[ls.keys.size()];
                for (int i = 0; i < ls.keys.size(); i++) keys[i] = ls.keys.get(i);
                body.add(new LookupSwitchInsnNode(dflt, keys, labels));
                continue;
            }

            body.add(insn.clone(labelMap));
        }

        body.add(endLabel);

        InsnList full = new InsnList();
        full.add(prologue);
        full.add(body);
        caller.instructions.insertBefore(invoke, full);
        if (aloadToRemove != null) {
            caller.instructions.remove(aloadToRemove);
        }
        caller.instructions.remove(invoke);

        caller.maxLocals = Math.max(caller.maxLocals, slotOffset + callee.maxLocals);

        if (callee.tryCatchBlocks != null && !callee.tryCatchBlocks.isEmpty()) {
            for (TryCatchBlockNode tcb : callee.tryCatchBlocks) {
                LabelNode start = labelMap.computeIfAbsent(tcb.start, k -> new LabelNode());
                LabelNode end = labelMap.computeIfAbsent(tcb.end, k -> new LabelNode());
                LabelNode handler = labelMap.computeIfAbsent(tcb.handler, k -> new LabelNode());
                if (caller.tryCatchBlocks == null) {
                    caller.tryCatchBlocks = new ArrayList<>();
                }
                caller.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, tcb.type));
            }
        }
    }

    private static int remapSlot(int calleeSlot, int slotOffset, boolean shareState, int stateSlot) {
        if (calleeSlot == 0 && shareState) return stateSlot;
        return slotOffset + calleeSlot;
    }

    private static boolean calleeWritesSlotZero(MethodNode callee) {
        for (AbstractInsnNode insn : callee.instructions.toArray()) {
            if (insn instanceof VarInsnNode vi
                    && vi.var == 0
                    && (vi.getOpcode() == Opcodes.ASTORE
                            || vi.getOpcode() == Opcodes.ISTORE
                            || vi.getOpcode() == Opcodes.LSTORE
                            || vi.getOpcode() == Opcodes.FSTORE
                            || vi.getOpcode() == Opcodes.DSTORE)) {
                return true;
            }
            if (insn instanceof IincInsnNode ii && ii.var == 0) {
                return true;
            }
        }
        return false;
    }
}
