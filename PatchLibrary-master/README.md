# PatchLibrary

C++ ソースの変更を実行中のプログラムに反映させるライブラリ＆ツールです。  
変更を反映させたい部分は DLL に分離されている必要があり、主な用途としてはプラグインの開発中にホストプログラムを再起動することなく変更を反映させ、トライ＆エラーのサイクルを早める、といったものを想定しています。  

Test 以下には Unity のプラグインを実行中に更新する簡単なテストプロジェクトが含まれています。  
TestUnityProject を Unity で開いた状態で TestUnityPlugin をビルドすると、その変更がリアルタイムに反映されます。  
TestUnityPlugin プロジェクトはビルドイベント (ビルド後イベント) でこのツールを呼び、Unity.exe のプロセスに対して変更を適用しています。  


正確には、このツールは対象のプロセスがロードしている DLL の関数を差し替える、ということをします。  
DLL Injection を用いて対象プロセスに新しい DLL をロードさせ、旧 DLL の export 関数テーブルを新しい DLL の関数へ書き換えることで更新を実現しています。  
このため、ネイティブコードの DLL であれば C++ に限らず変更を適用できます。また、新しい DLL で新規に追加された export 関数はホストプログラムは認識できず、こういうケースでは再起動が必要になります。  

より技術的な詳細に興味があれば、以下のプロジェクトや blog 記事が参考になると思われます。   
https://github.com/i-saint/DynamicPatcher (本ツールはこれの簡易版的なものです)  
http://i-saint.hatenablog.com/entry/2013/06/06/212515  