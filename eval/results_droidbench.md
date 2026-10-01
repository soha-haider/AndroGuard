# FlowDroid integration on DroidBench (63 apps)

Precision **0.900**, recall **0.763**, F1 **0.826** (TP 45, FP 5, FN 14; unit = leaking sink)

| Category | TP | FP | FN |
|---|---|---|---|
| AndroidSpecific | 11 | 0 | 2 |
| GeneralJava | 15 | 5 | 7 |
| Lifecycle | 19 | 0 | 5 |

| App | Expected leaks | Found |
|---|---|---|
| AndroidSpecific/ApplicationModeling1 | 1 | 1 |
| AndroidSpecific/DirectLeak1 | 1 | 1 |
| AndroidSpecific/InactiveActivity | 0 | 0 |
| AndroidSpecific/Library2 | 1 | 1 |
| AndroidSpecific/LogNoLeak | 0 | 0 |
| AndroidSpecific/Obfuscation1 | 1 | 1 |
| AndroidSpecific/Parcel1 | 1 | 0 |
| AndroidSpecific/PrivateDataLeak1 | 1 | 1 |
| AndroidSpecific/PrivateDataLeak2 | 1 | 1 |
| AndroidSpecific/PrivateDataLeak3 | 2 | 1 |
| AndroidSpecific/PublicAPIField1 | 1 | 1 |
| AndroidSpecific/PublicAPIField2 | 2 | 2 |
| AndroidSpecific/View1 | 1 | 1 |
| GeneralJava/Clone1 | 1 | 0 |
| GeneralJava/Exceptions1 | 1 | 1 |
| GeneralJava/Exceptions2 | 1 | 1 |
| GeneralJava/Exceptions3 | 0 | 1 |
| GeneralJava/Exceptions4 | 1 | 0 |
| GeneralJava/Exceptions5 | 1 | 0 |
| GeneralJava/Exceptions6 | 1 | 1 |
| GeneralJava/Exceptions7 | 0 | 0 |
| GeneralJava/FactoryMethods1 | 2 | 2 |
| GeneralJava/Loop1 | 1 | 1 |
| GeneralJava/Loop2 | 1 | 1 |
| GeneralJava/Serialization1 | 1 | 0 |
| GeneralJava/SourceCodeSpecific1 | 1 | 1 |
| GeneralJava/StartProcessWithSecret1 | 1 | 1 |
| GeneralJava/StaticInitialization1 | 1 | 0 |
| GeneralJava/StaticInitialization2 | 1 | 1 |
| GeneralJava/StaticInitialization3 | 1 | 0 |
| GeneralJava/StringFormatter1 | 1 | 0 |
| GeneralJava/StringPatternMatching1 | 1 | 1 |
| GeneralJava/StringToCharArray1 | 1 | 1 |
| GeneralJava/StringToOutputStream1 | 1 | 2 |
| GeneralJava/UnreachableCode | 0 | 0 |
| GeneralJava/VirtualDispatch1 | 1 | 2 |
| GeneralJava/VirtualDispatch2 | 1 | 2 |
| GeneralJava/VirtualDispatch3 | 0 | 1 |
| GeneralJava/VirtualDispatch4 | 0 | 0 |
| Lifecycle/ActivityEventSequence1 | 1 | 1 |
| Lifecycle/ActivityEventSequence2 | 1 | 0 |
| Lifecycle/ActivityEventSequence3 | 1 | 1 |
| Lifecycle/ActivityLifecycle1 | 1 | 1 |
| Lifecycle/ActivityLifecycle2 | 1 | 1 |
| Lifecycle/ActivityLifecycle3 | 1 | 1 |
| Lifecycle/ActivityLifecycle4 | 1 | 1 |
| Lifecycle/ActivitySavedState1 | 1 | 1 |
| Lifecycle/ApplicationLifecycle1 | 1 | 1 |
| Lifecycle/ApplicationLifecycle2 | 1 | 1 |
| Lifecycle/ApplicationLifecycle3 | 1 | 1 |
| Lifecycle/AsynchronousEventOrdering1 | 1 | 1 |
| Lifecycle/BroadcastReceiverLifecycle1 | 1 | 0 |
| Lifecycle/BroadcastReceiverLifecycle2 | 1 | 1 |
| Lifecycle/BroadcastReceiverLifecycle3 | 1 | 1 |
| Lifecycle/EventOrdering1 | 1 | 1 |
| Lifecycle/FragmentLifecycle1 | 1 | 1 |
| Lifecycle/FragmentLifecycle2 | 1 | 0 |
| Lifecycle/ServiceEventSequence1 | 1 | 0 |
| Lifecycle/ServiceEventSequence2 | 1 | 0 |
| Lifecycle/ServiceEventSequence3 | 1 | 1 |
| Lifecycle/ServiceLifecycle1 | 1 | 1 |
| Lifecycle/ServiceLifecycle2 | 1 | 1 |
| Lifecycle/SharedPreferenceChanged1 | 1 | 1 |

## Notes
- FlowDroid 2.13 with its default sources and sinks, run through AndroGuard's wrapper (app/modules/m3_input_processor/dataflow.py). This checks the integration, not new analysis research.
