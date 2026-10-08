export default function Page() {
  return (
    <div className="min-h-screen flex">
      {/* القائمة الجانبية */}
      <aside className="w-64 bg-zinc-900 text-white p-4">
        <h2 className="text-xl font-bold mb-6">لوحة التحكم</h2>
        <ul className="space-y-2">
          <li className="p-2 rounded bg-zinc-800">الرئيسية</li>
          <li className="p-2 rounded hover:bg-zinc-800 cursor-pointer">المستخدمون</li>
          <li className="p-2 rounded hover:bg-zinc-800 cursor-pointer">الإعدادات</li>
        </ul>
      </aside>

      {/* المحتوى */}
      <main className="flex-1 bg-zinc-50 p-8">
        <h1 className="text-2xl font-bold mb-6">نظرة عامة</h1>

        <div className="grid grid-cols-3 gap-4">
          <div className="bg-white p-6 rounded-lg shadow">
            <p className="text-sm text-zinc-500">المستخدمون</p>
            <p className="text-3xl font-bold mt-2">1,234</p>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <p className="text-sm text-zinc-500">الطلبات</p>
            <p className="text-3xl font-bold mt-2">5,678</p>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <p className="text-sm text-zinc-500">الإيرادات</p>
            <p className="text-3xl font-bold mt-2">$12,345</p>
          </div>
        </div>
      </main>
    </div>
  );
}
