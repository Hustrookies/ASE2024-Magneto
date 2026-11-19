package com.magneto.staticanalysis.projection;

import com.magneto.staticanalysis.MethodCallChain;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 链级投影入口（SPEC 3.3）：每条链只分析一次，结果缓存后供静态分析输出与 fuzz 阶段共用。
 * 缓存键为 MethodCallChain，其 equals/hashCode 基于方法签名序列。
 */
@Slf4j
public class ChainProjectionService {

    private final ProjectionAnalyzer analyzer;

    private final Map<MethodCallChain, ChainProjection> cache = new LinkedHashMap<>();

    public ChainProjectionService(int maxDepth) {
        this(new ProjectionAnalyzer(maxDepth));
    }

    public ChainProjectionService(ProjectionAnalyzer analyzer) {
        this.analyzer = analyzer;
    }

    public List<ChainProjection> analyzeAll(List<MethodCallChain> chains) {
        List<ChainProjection> projections = new ArrayList<>();
        for (int i = 0; i < chains.size(); i++) {
            projections.add(analyze(chains.get(i), "chain-" + i));
        }
        return projections;
    }

    public ChainProjection analyze(MethodCallChain chain) {
        ChainProjection cached = cache.get(chain);
        if (cached != null) {
            return cached;
        }
        return analyze(chain, "chain-" + Integer.toHexString(chain.hashCode()));
    }

    public ChainProjection getCached(MethodCallChain chain) {
        return cache.get(chain);
    }

    private ChainProjection analyze(MethodCallChain chain, String chainId) {
        ChainProjection projection = new ChainProjection(chainId);
        for (StepProjection step : analyzer.analyzeChain(chain)) {
            projection.addStep(step);
        }
        fillProjectedConstraints(projection);
        cache.put(chain, projection);
        log.info("projection analysed: {} steps={} breakpoints={}",
                chainId, projection.getSteps().size(), projection.getBreakpointCount());
        return projection;
    }

    /**
     * 沿链反向传播要求值并渲染每步的约束文本（SPEC S3）。
     * classify 阶段还没有 PoC 具体值，用占位文本；S4 在 fuzz 阶段拿到 Context 后重新渲染。
     */
    private static void fillProjectedConstraints(ChainProjection projection) {
        List<StepProjection> steps = projection.getSteps();
        if (steps.isEmpty()) {
            return;
        }

        Map<Integer, String> pocRequirements = new LinkedHashMap<>();
        for (ParamProjection param : steps.get(0).getParamProjections()) {
            pocRequirements.put(param.getCalleeArgIndex(),
                    ConstraintProjector.pocPlaceholder(param.getCalleeArgIndex()));
        }

        List<Map<Integer, String>> byDepth = ConstraintProjector.propagateChain(projection, pocRequirements);
        for (int i = 0; i < steps.size(); i++) {
            steps.get(i).setProjectedConstraints(ConstraintProjector.render(steps.get(i), byDepth.get(i)));
        }
    }
}
