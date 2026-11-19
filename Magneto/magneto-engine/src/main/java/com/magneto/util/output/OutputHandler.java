package com.magneto.util.output;



import com.magneto.dependency.MavenDependencyChain;
import com.magneto.staticanalysis.MethodCallChain;
import com.magneto.staticanalysis.projection.ChainProjection;

import java.util.List;

public interface OutputHandler {
    void outputDependencyChain(List<MavenDependencyChain> dependencyChains);

    void outputMethodCallChain(List<MethodCallChain> methodCallChains);

    void outputMethodCallChain(String fileName, List<MethodCallChain> methodCallChains);

    /** 默认空实现：只有 JSON handler 需要落盘 projection.json。 */
    default void outputProjection(List<ChainProjection> projections) {
    }

}
