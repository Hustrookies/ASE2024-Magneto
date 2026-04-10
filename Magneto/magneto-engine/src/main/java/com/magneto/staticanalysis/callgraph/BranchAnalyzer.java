package com.magneto.staticanalysis.callgraph;

import com.magneto.staticanalysis.MethodCall;
import soot.Body;
import soot.Unit;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import java.util.HashSet;
import java.util.Set;

/**
 * 分支分数分析器：计算控制流图路径数量
 */
public class BranchAnalyzer {
    private static final int MAX_PATH_LIMIT = 50; // 限制路径数量，避免爆炸
    public static int compute(MethodCall caller, MethodCall callee) {
        try {
            Body body = caller.getSootMethod().retrieveActiveBody();
            UnitGraph cfg = new ExceptionalUnitGraph(body);
            Unit target = null;
            // 找到调用 callee 的语句
            for (Unit unit : body.getUnits()) {
                if (unit.toString().contains(callee.getMethodName())) {
                    target = unit;
                    break;
                }
            }
            if (target == null) return 0;
            // 统计所有从入口到 target 的路径数
            Set<Unit> visited = new HashSet<>();
            return countPaths(cfg.getHeads().get(0), target, cfg, visited);
        } catch (Exception e) {
            return 0;
        }
    }
    //限制路径数量，避免爆炸
    private static int countPaths(Unit current, Unit target, UnitGraph cfg, Set<Unit> visited) {
        if (current.equals(target)) return 1;
        visited.add(current);
        int paths = 0;
        for (Unit succ : cfg.getSuccsOf(current)) {
            if (!visited.contains(succ)) {
                paths += countPaths(succ, target, cfg, new HashSet<>(visited));
                if (paths >= MAX_PATH_LIMIT) {
                return MAX_PATH_LIMIT;
            }
            }
        }
        return paths;
    }
}