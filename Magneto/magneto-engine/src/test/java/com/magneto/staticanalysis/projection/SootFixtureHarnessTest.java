package com.magneto.staticanalysis.projection;

import com.magneto.staticanalysis.projection.fixture.ComplexConstructionFixture;
import com.magneto.staticanalysis.projection.fixture.ConcatFixture;
import com.magneto.staticanalysis.projection.fixture.ConditionalSelectFixture;
import com.magneto.staticanalysis.projection.fixture.GuardedCallFixture;
import com.magneto.staticanalysis.projection.fixture.ParamGuardFixture;
import com.magneto.staticanalysis.projection.fixture.PassthroughFixture;
import com.magneto.staticanalysis.projection.fixture.SimpleDerivationFixture;
import com.magneto.staticanalysis.projection.fixture.UnresolvableFixture;
import org.junit.Test;
import soot.Body;
import soot.Unit;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * 验证最小 Soot 环境能在单测里跑起来——分类器的全部单测都依赖它。
 */
public class SootFixtureHarnessTest {

    @Test
    public void bootsSootAndResolvesAFixtureBody() {
        Body body = SootFixtureHarness.bodyOf(PassthroughFixture.class, "caller");

        assertNotNull(body);
        assertTrue(body.getUnits().size() > 0);
    }

    @Test
    public void locatesTheCallSiteOfTheCallee() {
        Body body = SootFixtureHarness.bodyOf(PassthroughFixture.class, "caller");

        Unit invoke = SootFixtureHarness.invokeOf(body, "callee");

        assertNotNull(invoke);
    }

    @Test
    public void resolvesEveryFixture() {
        Class<?>[] fixtures = {
                PassthroughFixture.class, SimpleDerivationFixture.class, ConcatFixture.class,
                ComplexConstructionFixture.class, ConditionalSelectFixture.class,
                GuardedCallFixture.class, ParamGuardFixture.class, UnresolvableFixture.class
        };

        for (Class<?> fixture : fixtures) {
            assertNotNull(fixture.getSimpleName(), SootFixtureHarness.bodyOf(fixture, "caller"));
        }
    }
}
