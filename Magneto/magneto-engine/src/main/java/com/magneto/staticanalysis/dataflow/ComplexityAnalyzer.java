package com.magneto.staticanalysis.dataflow;

import com.magneto.staticanalysis.MethodCall;
import soot.Body;
import soot.SootField;
import soot.Unit;
import soot.Value;
import soot.jimple.IfStmt;
import java.util.HashSet;
import java.util.Set;

/**
 * 复杂度分数分析器：统计类型数量、字段数量、条件数量
 */
public class ComplexityAnalyzer {
    public static int compute(MethodCall caller, MethodCall callee) {
        // 统计数据流路径上涉及的类型数量、需要初始化字段数量、需要满足的显示条件数量
        // 这里只做简单静态统计，实际可根据需要扩展
        //toDO
        try {
            Body body = caller.getSootMethod().retrieveActiveBody();
            Set<String> typeSet = new HashSet<>();
            Set<String> fieldSet = new HashSet<>();
            int conditionCount = 0;
            for (Unit unit : body.getUnits()) {
                for (soot.ValueBox vb : unit.getUseAndDefBoxes()) {
                    Value v = vb.getValue();
                    typeSet.add(v.getType().toString());
                }
                // 字段统计
                if (unit.toString().contains(".") && unit.toString().contains("<")) {
                    // 粗略统计字段
                    fieldSet.add(unit.toString());
                }
                // 条件统计
                if (unit instanceof IfStmt) {
                    conditionCount++;
                }
            }
            // 复杂度分数可加权求和todo
            return typeSet.size() + fieldSet.size() + conditionCount;
        } catch (Exception e) {
            return 0;
        }
    }
}