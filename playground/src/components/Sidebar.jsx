import "./Sidebar.css";

function Sidebar({ activeTab }) {
  const toolItems = [
    { name: "Scanner", icon: "S", active: activeTab === "scanner",  },
    { name: "Validator", icon: "V", active: activeTab === "validator" },
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-section">
        <div className="sidebar-title">Tools</div>
        {toolItems.map((item) => (
          <div
            key={item.name}
            className={`sidebar-item ${item.active ? "active" : ""}`}
          >
            <div className="file-icon">{item.icon}</div>
            {item.name}
          </div>
        ))}
      </div>
    </div>
  );
}

export default Sidebar;
